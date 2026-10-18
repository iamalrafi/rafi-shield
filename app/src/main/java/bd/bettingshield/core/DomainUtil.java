package bd.bettingshield.core;

import java.net.IDN;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Domain/URL cleaning and validation. Pure Java (no Android classes) so it can be unit tested anywhere.
 *
 * Safety rule: a domain on the PROTECTED list can never be blocked, even if a (wrong or malicious)
 * blocklist contains it. This is the main defence against accidental blocking of normal services.
 */
public final class DomainUtil {

    private DomainUtil() {}

    /** Domains (and all their subdomains) that must never be blocked. */
    private static final Set<String> PROTECTED = new HashSet<>(Arrays.asList(
            // Search / video / social / mail / messaging
            "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gmail.com",
            "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com",
            "facebook.com", "fbcdn.net", "messenger.com", "instagram.com", "whatsapp.com", "whatsapp.net",
            "microsoft.com", "live.com", "outlook.com", "office.com", "bing.com",
            "apple.com", "icloud.com", "telegram.org", "t.me",
            "wikipedia.org", "wikimedia.org", "github.com", "githubusercontent.com",
            "cloudflare.com", "amazonaws.com", "mozilla.org",
            // Education / news (examples)
            "khanacademy.org", "coursera.org", "edx.org", "bbc.com", "bbc.co.uk", "prothomalo.com",
            "thedailystar.net", "bdnews24.com", "kalerkantho.com",
            // Mobile financial services and banks in Bangladesh (examples)
            "bkash.com", "nagad.com.bd", "dutchbanglabank.com", "brac.net", "bracbank.com",
            "islamibankbd.com", "ebl.com.bd", "citybankplc.com", "sonalibank.com.bd",
            "upaybd.com", "rocket.com.bd", "bb.org.bd",
            // Government / education TLD-like suffixes in Bangladesh
            "gov.bd", "edu.bd", "ac.bd", "mil.bd"
    ));

    /** A few public suffixes: blocking these alone would block a whole country/category. */
    private static final Set<String> PUBLIC_SUFFIXES = new HashSet<>(Arrays.asList(
            "com.bd", "net.bd", "org.bd", "co.bd", "info.bd", "co.uk", "org.uk", "com.au", "co.in",
            "com.pk", "co.za", "com.br", "blogspot.com", "github.io", "pages.dev", "workers.dev",
            "herokuapp.com", "vercel.app", "netlify.app", "web.app", "firebaseapp.com"
    ));

    /** True if host equals a protected domain or is a subdomain of one. */
    public static boolean isProtected(String host) {
        if (host == null) return false;
        String h = host;
        while (true) {
            if (PROTECTED.contains(h)) return true;
            int dot = h.indexOf('.');
            if (dot < 0) return false;
            h = h.substring(dot + 1);
        }
    }

    /**
     * Turns a user-entered URL or domain into a clean lowercase ASCII host name,
     * or returns null if it is not a valid public domain name.
     * Examples: "https://WWW.Example.com:8080/path?x=1" -> "www.example.com"
     */
    public static String normalizeHost(String input) {
        if (input == null) return null;
        String s = input.trim();
        if (s.isEmpty() || s.length() > 2048) return null;

        int scheme = s.indexOf("://");
        if (scheme >= 0) s = s.substring(scheme + 3);
        else if (s.startsWith("//")) s = s.substring(2);

        int cut = indexOfAny(s, "/?#");
        if (cut >= 0) s = s.substring(0, cut);

        int at = s.lastIndexOf('@');
        if (at >= 0) s = s.substring(at + 1);

        if (s.startsWith("[")) return null; // IPv6 literal

        int colon = s.indexOf(':');
        if (colon >= 0) {
            String port = s.substring(colon + 1);
            if (!port.matches("\\d{1,5}")) return null;
            s = s.substring(0, colon);
        }

        while (s.endsWith(".")) s = s.substring(0, s.length() - 1);
        if (s.isEmpty()) return null;

        try {
            s = IDN.toASCII(s, IDN.ALLOW_UNASSIGNED);
        } catch (IllegalArgumentException e) {
            return null;
        }
        s = s.toLowerCase(Locale.ROOT);
        return isValidHost(s) ? s : null;
    }

    /** Strict syntax check of an already-lowercase ASCII host name. */
    public static boolean isValidHost(String h) {
        if (h == null || h.length() < 4 || h.length() > 253) return false;
        String[] labels = h.split("\\.", -1);
        if (labels.length < 2) return false;
        for (String l : labels) {
            if (l.isEmpty() || l.length() > 63) return false;
            if (l.charAt(0) == '-' || l.charAt(l.length() - 1) == '-') return false;
            for (int i = 0; i < l.length(); i++) {
                char c = l.charAt(i);
                boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
                if (!ok) return false;
            }
        }
        String tld = labels[labels.length - 1];
        // The top-level label must contain a letter (this rejects IPv4 addresses like 1.2.3.4).
        boolean hasLetter = false;
        for (int i = 0; i < tld.length(); i++) {
            char c = tld.charAt(i);
            if (c >= 'a' && c <= 'z') { hasLetter = true; break; }
        }
        return hasLetter;
    }

    /** True if blocking this exact entry would be too broad (a whole public suffix). */
    public static boolean isPublicSuffix(String host) {
        return PUBLIC_SUFFIXES.contains(host);
    }

    /**
     * Whether this normalized host may be added to a blocklist at all.
     */
    public static boolean isBlockable(String host) {
        return host != null && isValidHost(host) && !isProtected(host) && !isPublicSuffix(host);
    }

    private static int indexOfAny(String s, String chars) {
        for (int i = 0; i < s.length(); i++) {
            if (chars.indexOf(s.charAt(i)) >= 0) return i;
        }
        return -1;
    }
}
