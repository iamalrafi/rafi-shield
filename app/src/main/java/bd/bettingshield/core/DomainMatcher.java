package bd.bettingshield.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Holds the blocklist in memory and answers "is this host blocked?".
 *
 * Matching happens on whole labels: an entry "example.com" blocks "example.com" and
 * "a.b.example.com" but NOT "notexample.com" or "example.com.evil.org".
 */
public final class DomainMatcher {

    /** Result of parsing a list file. */
    public static final class Parsed {
        public final Set<String> domains = new HashSet<>();
        /** Brand words ("kw:word" lines): block any host whose name contains the word. */
        public final Set<String> keywords = new HashSet<>();
        /** Allowed domains ("ok:domain" lines): never blocked by a keyword rule. */
        public final Set<String> exceptions = new HashSet<>();
        public int rejectedLines = 0;
        public int protectedSkipped = 0;
    }

    private static final class Data {
        final Set<String> domains;
        final Set<String> keywords;
        final Set<String> exceptions;

        Data(Set<String> d, Set<String> k, Set<String> e) {
            domains = d;
            keywords = k;
            exceptions = e;
        }
    }

    private volatile Data data = new Data(new HashSet<>(), new HashSet<>(), new HashSet<>());

    public int size() {
        return data.domains.size();
    }

    public int keywordCount() {
        return data.keywords.size();
    }

    public void replace(Set<String> newDomains) {
        replace(newDomains, new HashSet<>(), new HashSet<>());
    }

    public void replace(Set<String> newDomains, Set<String> newKeywords, Set<String> newExceptions) {
        this.data = new Data(newDomains, newKeywords, newExceptions); // atomic swap; readers never see a half-built list
    }

    /**
     * @return the blocklist entry that matched, or null if the host is allowed.
     */
    public String match(String host) {
        if (host == null) return null;
        String h = host.toLowerCase(Locale.ROOT);
        while (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        if (h.isEmpty()) return null;

        // Defence in depth: protected services are never blocked, whatever the list says.
        if (DomainUtil.isProtected(h)) return null;

        Data d = data;
        String candidate = h;
        while (true) {
            if (d.domains.contains(candidate)) return candidate;
            int dot = candidate.indexOf('.');
            if (dot < 0) break;
            candidate = candidate.substring(dot + 1);
        }
        return matchKeyword(h, d);
    }

    /** Keyword rules: the host name (without its last label, e.g. .com) contains a listed brand word. */
    private static String matchKeyword(String h, Data d) {
        if (d.keywords.isEmpty()) return null;
        // An explicitly allowed domain (or a subdomain of one) is never blocked by a keyword.
        String c = h;
        while (true) {
            if (d.exceptions.contains(c)) return null;
            int dot = c.indexOf('.');
            if (dot < 0) break;
            c = c.substring(dot + 1);
        }
        int last = h.lastIndexOf('.');
        String core = last > 0 ? h.substring(0, last) : h;
        for (String k : d.keywords) {
            if (core.contains(k)) return "kw:" + k;
        }
        return null;
    }

    /**
     * Parses list text. Accepts one domain per line, or hosts-file lines like "0.0.0.0 example.com".
     * '#' starts a comment. Invalid or unsafe entries are skipped and counted.
     */
    public static Parsed parse(InputStream in) throws IOException {
        Parsed result = new Parsed();
        BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String line;
        while ((line = r.readLine()) != null) {
            int hash = line.indexOf('#');
            if (hash >= 0) line = line.substring(0, hash);
            line = line.trim();
            if (line.isEmpty()) continue;

            String lower = line.toLowerCase(Locale.ROOT);
            if (lower.startsWith("kw:")) {          // brand word rule
                String k = lower.substring(3).trim();
                if (DomainUtil.isValidKeyword(k)) result.keywords.add(k);
                else result.rejectedLines++;
                continue;
            }
            if (lower.startsWith("ok:")) {          // domain that keyword rules must not block
                String host = DomainUtil.normalizeHost(lower.substring(3).trim());
                if (host != null) result.exceptions.add(host);
                else result.rejectedLines++;
                continue;
            }

            String[] parts = line.split("\\s+");
            String token;
            if (parts.length == 1) {
                token = parts[0];
            } else if (parts.length == 2 && (parts[0].equals("0.0.0.0") || parts[0].equals("127.0.0.1"))) {
                token = parts[1];
            } else {
                result.rejectedLines++;
                continue;
            }

            // Reject anything that is not a plain host name (no wildcards, URLs, paths, ports).
            if (token.contains("*") || token.contains("/") || token.contains(":") || token.contains("@")) {
                result.rejectedLines++;
                continue;
            }
            String host = DomainUtil.normalizeHost(token);
            if (host == null) {
                result.rejectedLines++;
                continue;
            }
            if (DomainUtil.isProtected(host) || DomainUtil.isPublicSuffix(host)) {
                result.protectedSkipped++;
                continue;
            }
            result.domains.add(host);
        }
        return result;
    }
}
