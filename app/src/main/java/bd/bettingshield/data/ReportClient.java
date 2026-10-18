package bd.bettingshield.data;

import android.content.Context;
import bd.bettingshield.BuildConfig;
import bd.bettingshield.core.DomainUtil;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Sends "this looks like a betting site" reports to the review service and tracks their status.
 * Only the cleaned domain name, an optional short note and a random report id are sent.
 * No account, phone number, browsing history or device identifier is sent.
 */
public final class ReportClient {

    public static final String[] STATUSES = {
            "pending_review", "under_review", "approved", "rejected", "already_listed"};

    private ReportClient() {}

    public static boolean isConfigured() {
        return BuildConfig.REPORT_ENDPOINT != null && !BuildConfig.REPORT_ENDPOINT.isEmpty();
    }

    public static final class Report {
        public final String id;
        public final String domain;
        public final long time;
        public final String status;

        Report(String id, String domain, long time, String status) {
            this.id = id;
            this.domain = domain;
            this.time = time;
            this.status = status;
        }
    }

    public static final class SubmitResult {
        public final boolean ok;
        public final String status;   // one of STATUSES when ok
        public final String error;    // short code when !ok

        SubmitResult(boolean ok, String status, String error) {
            this.ok = ok;
            this.status = status;
            this.error = error;
        }
    }

    public static List<Report> mine(Context c) {
        List<Report> out = new ArrayList<>();
        String raw = Prefs.reports(c);
        if (raw.isEmpty()) return out;
        for (String line : raw.split("\n")) {
            String[] p = line.split("\\|");
            if (p.length != 4) continue;
            try {
                out.add(new Report(p[0], p[1], Long.parseLong(p[2]), p[3]));
            } catch (NumberFormatException ignored) {
                // skip
            }
        }
        return out;
    }

    private static void save(Context c, List<Report> list) {
        StringBuilder sb = new StringBuilder();
        for (Report r : list) {
            sb.append(r.id).append('|').append(r.domain).append('|').append(r.time).append('|')
                    .append(r.status).append('\n');
        }
        Prefs.setReports(c, sb.toString());
    }

    /** Blocking network call: run on a background thread. {@code kind} is "betting" or "false_positive". */
    public static SubmitResult submit(Context c, String domain, String kind, String note) {
        if (!isConfigured()) return new SubmitResult(false, null, "not_configured");
        String host = DomainUtil.normalizeHost(domain);
        if (host == null) return new SubmitResult(false, null, "invalid_url");
        if (note == null) note = "";
        if (note.length() > 200) note = note.substring(0, 200);

        String id = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        try {
            JSONObject body = new JSONObject();
            body.put("id", id);
            body.put("domain", host);
            body.put("kind", kind);
            body.put("note", note);
            JSONObject res = postJson(BuildConfig.REPORT_ENDPOINT + "/report", body.toString());
            if (res.has("error")) return new SubmitResult(false, null, res.getString("error"));
            String status = res.optString("status", "pending_review");
            List<Report> list = mine(c);
            list.add(0, new Report(id, host, System.currentTimeMillis(), status));
            while (list.size() > 50) list.remove(list.size() - 1);
            save(c, list);
            return new SubmitResult(true, status, null);
        } catch (IOException | JSONException e) {
            return new SubmitResult(false, null, "network");
        }
    }

    /** Asks the service for the current status of all my reports. Blocking. */
    public static void refreshStatuses(Context c) {
        if (!isConfigured()) return;
        List<Report> list = mine(c);
        List<Report> updated = new ArrayList<>();
        for (Report r : list) {
            String status = r.status;
            try {
                JSONObject res = getJson(BuildConfig.REPORT_ENDPOINT + "/status/" + r.id);
                String s = res.optString("status", "");
                for (String known : STATUSES) {
                    if (known.equals(s)) status = s;
                }
            } catch (IOException | JSONException ignored) {
                // keep the old status
            }
            updated.add(new Report(r.id, r.domain, r.time, status));
        }
        save(c, updated);
    }

    private static JSONObject postJson(String url, String json) throws IOException, JSONException {
        HttpURLConnection h = (HttpURLConnection) new URL(url).openConnection();
        try {
            h.setConnectTimeout(15000);
            h.setReadTimeout(20000);
            h.setRequestMethod("POST");
            h.setDoOutput(true);
            h.setRequestProperty("Content-Type", "application/json");
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            try (OutputStream o = h.getOutputStream()) {
                o.write(bytes);
            }
            return new JSONObject(readAll(h));
        } finally {
            h.disconnect();
        }
    }

    private static JSONObject getJson(String url) throws IOException, JSONException {
        HttpURLConnection h = (HttpURLConnection) new URL(url).openConnection();
        try {
            h.setConnectTimeout(15000);
            h.setReadTimeout(20000);
            return new JSONObject(readAll(h));
        } finally {
            h.disconnect();
        }
    }

    private static String readAll(HttpURLConnection h) throws IOException {
        int code = h.getResponseCode();
        InputStream in = code >= 400 ? h.getErrorStream() : h.getInputStream();
        if (in == null) throw new IOException("no body, status " + code);
        try (InputStream is = in) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = is.read(buf)) > 0) {
                bos.write(buf, 0, n);
                if (bos.size() > 100_000) throw new IOException("response too large");
            }
            return new String(bos.toByteArray(), StandardCharsets.UTF_8);
        }
    }
}
