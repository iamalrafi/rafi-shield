package bd.bettingshield.core;

import java.util.Locale;

/** Minimal DNS message helpers: read the question of a query and build a "blocked" answer. */
public final class DnsMessage {

    private DnsMessage() {}

    public static final class Question {
        public final String name;
        public final int type;
        /** Offset just after the question section (relative to the start of the DNS message). */
        public final int endOffset;

        Question(String name, int type, int endOffset) {
            this.name = name;
            this.type = type;
            this.endOffset = endOffset;
        }
    }

    /**
     * Reads the first question of a DNS query.
     * @return null if the packet is not a normal single-question query (then it should just be forwarded).
     */
    public static Question parseQuestion(byte[] d, int off, int len) {
        if (len < 12) return null;
        int flags = u16(d, off + 2);
        boolean isResponse = (flags & 0x8000) != 0;
        int opcode = (flags >> 11) & 0xF;
        int qd = u16(d, off + 4);
        if (isResponse || opcode != 0 || qd < 1) return null;

        int p = off + 12;
        int end = off + len;
        StringBuilder name = new StringBuilder();
        while (true) {
            if (p >= end) return null;
            int l = d[p] & 0xFF;
            p++;
            if (l == 0) break;
            if ((l & 0xC0) != 0) return null; // compression pointers are not valid in a query question
            if (p + l > end) return null;
            if (name.length() > 0) name.append('.');
            for (int i = 0; i < l; i++) {
                name.append((char) (d[p + i] & 0xFF));
            }
            p += l;
            if (name.length() > 253) return null;
        }
        if (p + 4 > end) return null;
        int type = u16(d, p);
        p += 4; // type + class
        return new Question(name.toString().toLowerCase(Locale.ROOT), type, p - off);
    }

    /**
     * Builds a "domain does not exist" (NXDOMAIN) answer for the given query.
     * The response copies the question section and has no answer records.
     */
    public static byte[] buildBlockedResponse(byte[] d, int off, int len, Question q) {
        int qEnd = q.endOffset; // relative
        byte[] out = new byte[qEnd];
        System.arraycopy(d, off, out, 0, qEnd);
        int reqFlags = u16(d, off + 2);
        int opcode = (reqFlags >> 11) & 0xF;
        int rd = (reqFlags >> 8) & 1;
        int flags = 0x8000 | (opcode << 11) | (rd << 8) | 0x0080 /* RA */ | 3 /* NXDOMAIN */;
        out[2] = (byte) (flags >> 8);
        out[3] = (byte) flags;
        // QDCOUNT = 1, ANCOUNT = NSCOUNT = ARCOUNT = 0
        out[4] = 0; out[5] = 1;
        out[6] = 0; out[7] = 0;
        out[8] = 0; out[9] = 0;
        out[10] = 0; out[11] = 0;
        return out;
    }

    static int u16(byte[] b, int i) {
        return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
    }
}
