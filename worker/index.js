// Betting Shield BD - report service (Cloudflare Workers, free plan).
//
// Needs:  KV namespace binding  REPORTS
//         secret                ADMIN_TOKEN   (a long random text only you know)
//         variable (optional)   LIST_URL      (raw URL of blocklist/blocklist.txt, to detect "already listed")
//
// Endpoints used by the app:   POST /report      GET /status/<id>
// Endpoints for the reviewer:  GET /admin  (web page)   GET /admin/list   POST /admin/set   GET /admin/export

const PROTECTED = [
  "google.com", "googleapis.com", "gstatic.com", "gmail.com", "youtube.com", "youtu.be", "facebook.com",
  "fbcdn.net", "messenger.com", "instagram.com", "whatsapp.com", "microsoft.com", "live.com", "outlook.com",
  "apple.com", "icloud.com", "telegram.org", "wikipedia.org", "github.com", "cloudflare.com", "amazonaws.com",
  "bkash.com", "nagad.com.bd", "dutchbanglabank.com", "brac.net", "bracbank.com", "islamibankbd.com",
  "ebl.com.bd", "citybankplc.com", "sonalibank.com.bd", "rocket.com.bd", "bb.org.bd",
  "gov.bd", "edu.bd", "ac.bd", "mil.bd",
];
const PUBLIC_SUFFIXES = ["com.bd", "net.bd", "org.bd", "co.bd", "co.uk", "blogspot.com", "github.io", "pages.dev", "workers.dev"];
const STATUSES = ["pending_review", "under_review", "approved", "rejected", "already_listed"];
const MAX_REPORTS_PER_HOUR = 10;

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8" } });

export function normalizeHost(input) {
  if (typeof input !== "string") return null;
  let s = input.trim().toLowerCase();
  if (!s || s.length > 2048) return null;
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/^\/\//, "");
  s = s.split(/[/?#]/)[0];
  if (s.includes("@")) s = s.slice(s.lastIndexOf("@") + 1);
  if (s.startsWith("[")) return null;
  const colon = s.indexOf(":");
  if (colon >= 0) {
    if (!/^\d{1,5}$/.test(s.slice(colon + 1))) return null;
    s = s.slice(0, colon);
  }
  s = s.replace(/\.+$/, "");
  if (s.length < 4 || s.length > 253) return null;
  const labels = s.split(".");
  if (labels.length < 2) return null;
  for (const l of labels) {
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) return null;
  }
  if (!/[a-z]/.test(labels[labels.length - 1])) return null; // rejects IP addresses
  return s;
}

function isProtected(host) {
  return PROTECTED.some((p) => host === p || host.endsWith("." + p));
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function isAdmin(request, env) {
  const h = request.headers.get("authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  return !!env.ADMIN_TOKEN && env.ADMIN_TOKEN.length >= 16 && timingSafeEqual(token, env.ADMIN_TOKEN);
}

async function isListed(host, env) {
  if (!env.LIST_URL) return false;
  try {
    const res = await fetch(env.LIST_URL, { cf: { cacheTtl: 3600, cacheEverything: true } });
    if (!res.ok) return false;
    const entries = new Set(
      (await res.text()).split("\n").map((l) => l.trim().toLowerCase()).filter((l) => l && !l.startsWith("#"))
    );
    let h = host;
    while (true) {
      if (entries.has(h)) return true;
      const dot = h.indexOf(".");
      if (dot < 0) return false;
      h = h.slice(dot + 1);
    }
  } catch {
    return false;
  }
}

async function handleReport(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid_request" }, 400);
  }
  const id = String(body.id || "");
  const kind = body.kind;
  const host = normalizeHost(body.domain);
  const note = String(body.note || "").slice(0, 200);
  if (!/^[a-f0-9]{16}$/.test(id) || !host || !["betting", "false_positive"].includes(kind)) {
    return json({ error: "invalid_url" }, 400);
  }
  if (kind === "betting" && (isProtected(host) || PUBLIC_SUFFIXES.includes(host))) {
    return json({ error: "protected" }, 400);
  }

  // Basic rate limit per network address (only a hash is kept, for one hour).
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const hour = Math.floor(Date.now() / 3600000);
  const rlKey = `rl:${(await sha256Hex(ip + ":" + hour)).slice(0, 24)}`;
  const used = parseInt((await env.REPORTS.get(rlKey)) || "0", 10);
  if (used >= MAX_REPORTS_PER_HOUR) return json({ error: "rate_limited" }, 429);
  await env.REPORTS.put(rlKey, String(used + 1), { expirationTtl: 3700 });

  // Duplicate detection: the same domain and kind is only queued once.
  const domKey = `dom:${kind}:${host}`;
  if (await env.REPORTS.get(domKey)) return json({ error: "duplicate" }, 409);

  let status = "pending_review";
  if (kind === "betting" && (await isListed(host, env))) status = "already_listed";

  const report = { id, domain: host, kind, note, status, created: new Date().toISOString() };
  await env.REPORTS.put(`r:${id}`, JSON.stringify(report));
  await env.REPORTS.put(domKey, id);
  return json({ id, status });
}

async function handleStatus(id, env) {
  if (!/^[a-f0-9]{16}$/.test(id)) return json({ error: "not_found" }, 404);
  const raw = await env.REPORTS.get(`r:${id}`);
  if (!raw) return json({ error: "not_found" }, 404);
  return json({ status: JSON.parse(raw).status });
}

async function allReports(env) {
  const out = [];
  let cursor;
  do {
    const page = await env.REPORTS.list({ prefix: "r:", cursor });
    for (const k of page.keys) {
      const raw = await env.REPORTS.get(k.name);
      if (raw) out.push(JSON.parse(raw));
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  out.sort((a, b) => (a.created < b.created ? 1 : -1));
  return out;
}

const ADMIN_PAGE = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Betting Shield BD - review</title>
<style>body{font:15px system-ui;margin:16px;max-width:900px}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}
button{margin:2px;padding:6px 10px}.k{font-size:12px;color:#555}</style></head><body>
<h2>Report review</h2>
<p><button id="login">Enter admin token</button> <button id="exp">Export approved domains</button></p>
<pre id="out"></pre><table id="t"></table>
<script>
let token = sessionStorage.getItem("t") || "";
const api = (p, o={}) => fetch(p, {...o, headers: {...(o.headers||{}), authorization: "Bearer " + token, "content-type": "application/json"}});
async function load(){
  const r = await api("/admin/list"); const t = document.getElementById("t"); t.textContent = "";
  if(!r.ok){ t.textContent = "Not authorised"; return; }
  const list = await r.json();
  const head = t.insertRow(); ["Domain","Type","Note","Status","Set status"].forEach(h=>{const c=document.createElement("th");c.textContent=h;head.appendChild(c)});
  for(const x of list){
    const row = t.insertRow();
    row.insertCell().textContent = x.domain;
    row.insertCell().textContent = x.kind;
    row.insertCell().textContent = x.note;
    row.insertCell().textContent = x.status;
    const c = row.insertCell();
    for(const s of ["under_review","approved","rejected"]){
      const b = document.createElement("button"); b.textContent = s;
      b.onclick = async()=>{ await api("/admin/set",{method:"POST",body:JSON.stringify({id:x.id,status:s})}); load(); };
      c.appendChild(b);
    }
  }
}
document.getElementById("login").onclick = ()=>{ token = prompt("Admin token") || ""; sessionStorage.setItem("t", token); load(); };
document.getElementById("exp").onclick = async()=>{ const r = await api("/admin/export"); document.getElementById("out").textContent = await r.text(); };
if(token) load();
</script></body></html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    try {
      if (request.method === "POST" && path === "/report") return await handleReport(request, env);
      if (request.method === "GET" && path.startsWith("/status/")) return await handleStatus(path.slice(8), env);

      if (path === "/admin" && request.method === "GET") {
        return new Response(ADMIN_PAGE, { headers: { "content-type": "text/html; charset=utf-8", "x-frame-options": "DENY" } });
      }
      if (path.startsWith("/admin/")) {
        if (!isAdmin(request, env)) return json({ error: "unauthorized" }, 401);
        if (path === "/admin/list" && request.method === "GET") return json(await allReports(env));
        if (path === "/admin/set" && request.method === "POST") {
          const b = await request.json();
          if (!/^[a-f0-9]{16}$/.test(String(b.id)) || !STATUSES.includes(b.status)) return json({ error: "invalid_request" }, 400);
          const raw = await env.REPORTS.get(`r:${b.id}`);
          if (!raw) return json({ error: "not_found" }, 404);
          const rep = JSON.parse(raw);
          rep.status = b.status;
          await env.REPORTS.put(`r:${b.id}`, JSON.stringify(rep));
          return json({ ok: true });
        }
        if (path === "/admin/export" && request.method === "GET") {
          const list = await allReports(env);
          const add = list.filter((r) => r.status === "approved" && r.kind === "betting").map((r) => r.domain);
          const fix = list.filter((r) => r.status === "approved" && r.kind === "false_positive").map((r) => r.domain);
          const text =
            "# Paste into blocklist/manual.txt\n" + add.join("\n") +
            "\n\n# Paste into blocklist/allow.txt (wrongly blocked sites)\n" + fix.join("\n") + "\n";
          return new Response(text, { headers: { "content-type": "text/plain; charset=utf-8" } });
        }
      }
      return json({ error: "not_found" }, 404);
    } catch (e) {
      return json({ error: "server_error" }, 500);
    }
  },
};
