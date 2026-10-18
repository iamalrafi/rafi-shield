package bd.bettingshield.data;

import android.content.Context;
import android.content.res.AssetManager;
import bd.bettingshield.BuildConfig;
import bd.bettingshield.core.DomainMatcher;
import bd.bettingshield.core.ListSignature;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.HashSet;
import java.util.Set;

/**
 * Keeps the blocklist (domains) and the betting-app list on the device and updates them safely:
 * a new list replaces the old one only after it has been downloaded completely, its signature
 * has been verified and it passed sanity checks. Otherwise the previous list stays in use.
 */
public final class BlocklistStore {

    /** Shared matcher used by the VPN service. */
    public static final DomainMatcher MATCHER = new DomainMatcher();

    private static final String LIST_FILE = "blocklist.txt";
    private static final String APPS_FILE = "betting_apps.txt";
    private static final int MAX_BYTES = 5 * 1024 * 1024;

    private static volatile boolean loaded = false;
    private static volatile Set<String> appPackages = new HashSet<>();

    private BlocklistStore() {}

    public enum Status { UPDATED, UNCHANGED, FAILED, NOT_CONFIGURED }

    public static final class Result {
        public final Status status;
        public final String message;

        Result(Status status, String message) {
            this.status = status;
            this.message = message;
        }
    }

    /** Loads the list from disk (or from the bundled seed on first run). Safe to call many times. */
    public static synchronized void load(Context ctx) {
        if (loaded) return;
        Context app = ctx.getApplicationContext();
        File f = new File(app.getFilesDir(), LIST_FILE);
        try {
            if (!f.exists()) copyAsset(app, "blocklist_seed.txt", f);
            MATCHER.replace(parseFile(f));
        } catch (IOException e) {
            // Corrupt file on disk: fall back to the bundled seed.
            try {
                copyAsset(app, "blocklist_seed.txt", f);
                MATCHER.replace(parseFile(f));
            } catch (IOException ignored) {
                // leave whatever is in memory
            }
        }
        File af = new File(app.getFilesDir(), APPS_FILE);
        try {
            if (!af.exists()) copyAsset(app, "betting_apps_seed.txt", af);
            try (InputStream in = new java.io.FileInputStream(af)) {
                appPackages = readPackages(in);
            }
        } catch (IOException ignored) {
            appPackages = new HashSet<>();
        }
        loaded = true;
    }

    private static Set<String> parseFile(File f) throws IOException {
        try (InputStream in = new java.io.FileInputStream(f)) {
            DomainMatcher.Parsed p = DomainMatcher.parse(in);
            if (p.domains.isEmpty()) throw new IOException("empty list on disk");
            return p.domains;
        }
    }

    public static int domainCount() {
        return MATCHER.size();
    }

    public static Set<String> bettingAppPackages() {
        return appPackages;
    }

    /** Downloads and verifies the shared lists. Blocking: call from a background thread. */
    public static synchronized Result update(Context ctx, boolean force) {
        Context app = ctx.getApplicationContext();
        load(app);
        String base = BuildConfig.BLOCKLIST_BASE;
        if (base == null || base.isEmpty() || base.contains("YOUR_GITHUB_NAME")) {
            Prefs.saveUpdateResult(app, false, null, "not configured");
            return new Result(Status.NOT_CONFIGURED, "Blocklist address is not configured");
        }
        String pubKey = readPublicKey(app);
        try {
            // ---- domain list ----
            String etagToSend = force ? "" : Prefs.etag(app);
            Download d = download(base + "/blocklist.txt", etagToSend);
            if (d.notModified) {
                updateAppsQuietly(app, base, pubKey);
                Prefs.saveUpdateResult(app, true, null, "unchanged");
                return new Result(Status.UNCHANGED, "Already up to date");
            }
            if (!pubKey.isEmpty()) {
                Download sig = download(base + "/blocklist.txt.sig", "");
                String sigText = new String(sig.data, StandardCharsets.UTF_8);
                if (!ListSignature.verify(d.data, sigText, pubKey)) {
                    throw new IOException("signature check failed");
                }
            }
            DomainMatcher.Parsed p = DomainMatcher.parse(new ByteArrayInputStream(d.data));
            if (p.domains.isEmpty()) throw new IOException("downloaded list has no valid domains");
            int old = MATCHER.size();
            if (old >= 100 && p.domains.size() < old / 2) {
                throw new IOException("new list is suspiciously smaller (" + p.domains.size() + " vs " + old + ")");
            }
            File target = new File(app.getFilesDir(), LIST_FILE);
            writeAtomically(app, d.data, target);
            MATCHER.replace(p.domains);
            Prefs.saveUpdateResult(app, true, d.etag, "updated");

            updateAppsQuietly(app, base, pubKey);
            return new Result(Status.UPDATED, "Updated: " + p.domains.size() + " domains");
        } catch (Exception e) {
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            Prefs.saveUpdateResult(app, false, null, "failed: " + msg);
            return new Result(Status.FAILED, msg); // old list stays active
        }
    }

    // ---------------------------------------------------------------------------------------

    private static void updateAppsQuietly(Context app, String base, String pubKey) {
        try {
            Download d = download(base + "/betting_apps.txt", "");
            if (!pubKey.isEmpty()) {
                Download sig = download(base + "/betting_apps.txt.sig", "");
                if (!ListSignature.verify(d.data, new String(sig.data, StandardCharsets.UTF_8), pubKey)) return;
            }
            Set<String> pk = readPackages(new ByteArrayInputStream(d.data));
            if (pk.isEmpty()) return;
            writeAtomically(app, d.data, new File(app.getFilesDir(), APPS_FILE));
            appPackages = pk;
        } catch (Exception ignored) {
            // The apps list is optional; keep the old one.
        }
    }

    private static Set<String> readPackages(InputStream in) throws IOException {
        Set<String> out = new HashSet<>();
        java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(in, StandardCharsets.UTF_8));
        String line;
        while ((line = r.readLine()) != null) {
            int h = line.indexOf('#');
            if (h >= 0) line = line.substring(0, h);
            line = line.trim();
            if (line.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")) out.add(line);
        }
        in.close();
        return out;
    }

    private static final class Download {
        byte[] data;
        String etag;
        boolean notModified;
    }

    private static Download download(String url, String etag) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        try {
            c.setConnectTimeout(15000);
            c.setReadTimeout(20000);
            c.setRequestProperty("User-Agent", "BettingShieldBD/" + BuildConfig.VERSION_NAME);
            if (etag != null && !etag.isEmpty()) c.setRequestProperty("If-None-Match", etag);
            int code = c.getResponseCode();
            Download d = new Download();
            if (code == 304) {
                d.notModified = true;
                return d;
            }
            if (code != 200) throw new IOException("server answered " + code + " for " + shortName(url));
            d.etag = c.getHeaderField("ETag");
            try (InputStream in = c.getInputStream()) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[16384];
                int n;
                while ((n = in.read(buf)) > 0) {
                    bos.write(buf, 0, n);
                    if (bos.size() > MAX_BYTES) throw new IOException("file too large");
                }
                d.data = bos.toByteArray();
            }
            return d;
        } finally {
            c.disconnect();
        }
    }

    private static String shortName(String url) {
        int i = url.lastIndexOf('/');
        return i >= 0 ? url.substring(i + 1) : url;
    }

    private static void writeAtomically(Context app, byte[] data, File target) throws IOException {
        File tmp = new File(app.getFilesDir(), target.getName() + ".tmp");
        try (FileOutputStream o = new FileOutputStream(tmp)) {
            o.write(data);
            o.getFD().sync();
        }
        Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void copyAsset(Context app, String asset, File target) throws IOException {
        AssetManager am = app.getAssets();
        File tmp = new File(app.getFilesDir(), target.getName() + ".tmp");
        try (InputStream in = am.open(asset); FileOutputStream o = new FileOutputStream(tmp)) {
            byte[] buf = new byte[16384];
            int n;
            while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
        }
        Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
    }

    /** Public key used to verify lists (Base64, X.509). Empty string = signatures not enforced. */
    public static String readPublicKey(Context app) {
        try (InputStream in = app.getAssets().open("list_public_key.txt")) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            String s = new String(bos.toByteArray(), StandardCharsets.UTF_8).trim();
            return s.startsWith("#") ? "" : s;
        } catch (IOException e) {
            return "";
        }
    }

    public static boolean signaturesEnforced(Context app) {
        return !readPublicKey(app).isEmpty();
    }
}
