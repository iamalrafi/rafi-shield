package bd.bettingshield.data;

import android.content.Context;
import java.util.ArrayList;
import java.util.List;

/**
 * Remembers the most recent BLOCKED domains only (never the sites that were allowed),
 * so the user can see what was blocked and report a false positive. Stored on the device only.
 */
public final class BlockLog {

    private static final int MAX = 50;

    public static final class Entry {
        public final long time;
        public final String domain;
        public final String matchedEntry;

        Entry(long time, String domain, String matchedEntry) {
            this.time = time;
            this.domain = domain;
            this.matchedEntry = matchedEntry;
        }
    }

    private BlockLog() {}

    public static synchronized void add(Context c, String domain, String matchedEntry) {
        List<Entry> list = read(c);
        // Collapse immediate repeats of the same domain (apps retry a lot).
        if (!list.isEmpty() && list.get(0).domain.equals(domain)
                && System.currentTimeMillis() - list.get(0).time < 60_000) {
            Prefs.incrementBlocked(c);
            return;
        }
        list.add(0, new Entry(System.currentTimeMillis(), domain, matchedEntry));
        while (list.size() > MAX) list.remove(list.size() - 1);
        StringBuilder sb = new StringBuilder();
        for (Entry e : list) {
            sb.append(e.time).append('|').append(e.domain).append('|').append(e.matchedEntry).append('\n');
        }
        Prefs.setRecentBlocked(c, sb.toString());
        Prefs.incrementBlocked(c);
    }

    public static synchronized List<Entry> read(Context c) {
        List<Entry> out = new ArrayList<>();
        String raw = Prefs.recentBlocked(c);
        if (raw.isEmpty()) return out;
        for (String line : raw.split("\n")) {
            String[] p = line.split("\\|");
            if (p.length != 3) continue;
            try {
                out.add(new Entry(Long.parseLong(p[0]), p[1], p[2]));
            } catch (NumberFormatException ignored) {
                // skip bad line
            }
        }
        return out;
    }

    public static synchronized void clear(Context c) {
        Prefs.setRecentBlocked(c, "");
    }
}
