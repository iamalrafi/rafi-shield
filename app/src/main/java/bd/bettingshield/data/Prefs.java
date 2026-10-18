package bd.bettingshield.data;

import android.content.Context;
import android.content.SharedPreferences;

/** Small wrapper around SharedPreferences. Everything stays on the device. */
public final class Prefs {

    private static final String NAME = "betting_shield";

    private Prefs() {}

    private static SharedPreferences sp(Context c) {
        return c.getApplicationContext().getSharedPreferences(NAME, Context.MODE_PRIVATE);
    }

    /** The user wants protection on (used to restart it after reboot / process death). */
    public static boolean isProtectionWanted(Context c) {
        return sp(c).getBoolean("protection_wanted", false);
    }

    public static void setProtectionWanted(Context c, boolean v) {
        sp(c).edit().putBoolean("protection_wanted", v).apply();
    }

    /** "bn" (default) or "en". */
    public static String language(Context c) {
        return sp(c).getString("lang", "bn");
    }

    public static void setLanguage(Context c, String lang) {
        sp(c).edit().putString("lang", lang).apply();
    }

    public static long lastUpdateOk(Context c) {
        return sp(c).getLong("list_last_ok", 0L);
    }

    public static long lastUpdateCheck(Context c) {
        return sp(c).getLong("list_last_check", 0L);
    }

    public static String lastUpdateMessage(Context c) {
        return sp(c).getString("list_last_msg", "");
    }

    public static String etag(Context c) {
        return sp(c).getString("list_etag", "");
    }

    public static void saveUpdateResult(Context c, boolean ok, String etag, String message) {
        SharedPreferences.Editor e = sp(c).edit();
        long now = System.currentTimeMillis();
        e.putLong("list_last_check", now);
        e.putString("list_last_msg", message);
        if (ok) {
            e.putLong("list_last_ok", now);
            if (etag != null) e.putString("list_etag", etag);
        }
        e.apply();
    }

    public static long totalBlocked(Context c) {
        return sp(c).getLong("total_blocked", 0L);
    }

    public static void incrementBlocked(Context c) {
        SharedPreferences s = sp(c);
        s.edit().putLong("total_blocked", s.getLong("total_blocked", 0L) + 1).apply();
    }

    /** Recent blocked domains, newest first, one per line: "time|domain|matchedEntry". */
    public static String recentBlocked(Context c) {
        return sp(c).getString("recent_blocked", "");
    }

    public static void setRecentBlocked(Context c, String v) {
        sp(c).edit().putString("recent_blocked", v).apply();
    }

    /** Reports this device has sent, one per line: "id|domain|time|lastKnownStatus". */
    public static String reports(Context c) {
        return sp(c).getString("reports", "");
    }

    public static void setReports(Context c, String v) {
        sp(c).edit().putString("reports", v).apply();
    }
}
