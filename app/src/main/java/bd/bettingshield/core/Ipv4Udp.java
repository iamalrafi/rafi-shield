package bd.bettingshield.core;

/** Reads and builds IPv4 + UDP packets (enough for DNS-over-UDP on the VPN tunnel). */
public final class Ipv4Udp {

    private Ipv4Udp() {}

    /** A parsed IPv4/UDP packet. Offsets are relative to the start of the buffer passed to parse(). */
    public static final class Packet {
        public byte[] srcIp = new byte[4];
        public byte[] dstIp = new byte[4];
        public int srcPort;
        public int dstPort;
        public int payloadOffset;
        public int payloadLength;
    }

    /** @return the packet, or null if it is not a well-formed IPv4 UDP packet. */
    public static Packet parse(byte[] b, int len) {
        if (len < 28) return null;
        int version = (b[0] >> 4) & 0xF;
        if (version != 4) return null;
        int ihl = (b[0] & 0xF) * 4;
        if (ihl < 20 || len < ihl + 8) return null;
        int protocol = b[9] & 0xFF;
        if (protocol != 17) return null;
        int totalLen = ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
        if (totalLen > len || totalLen < ihl + 8) return null;
        // Fragmented packets are not handled (DNS queries are tiny).
        int fragField = ((b[6] & 0x1F) << 8) | (b[7] & 0xFF);
        if (fragField != 0) return null;

        Packet p = new Packet();
        System.arraycopy(b, 12, p.srcIp, 0, 4);
        System.arraycopy(b, 16, p.dstIp, 0, 4);
        p.srcPort = ((b[ihl] & 0xFF) << 8) | (b[ihl + 1] & 0xFF);
        p.dstPort = ((b[ihl + 2] & 0xFF) << 8) | (b[ihl + 3] & 0xFF);
        int udpLen = ((b[ihl + 4] & 0xFF) << 8) | (b[ihl + 5] & 0xFF);
        if (udpLen < 8 || ihl + udpLen > totalLen) return null;
        p.payloadOffset = ihl + 8;
        p.payloadLength = udpLen - 8;
        return p;
    }

    /**
     * Builds a reply packet: addresses and ports swapped relative to the request, with the given payload.
     */
    public static byte[] buildReply(Packet req, byte[] payload, int payloadLen) {
        int total = 20 + 8 + payloadLen;
        byte[] o = new byte[total];
        o[0] = 0x45;                       // IPv4, header length 20
        o[1] = 0;
        o[2] = (byte) (total >> 8);
        o[3] = (byte) total;
        o[4] = 0; o[5] = 0;                // identification
        o[6] = 0x40; o[7] = 0;             // don't fragment
        o[8] = 64;                         // TTL
        o[9] = 17;                         // UDP
        // reply source = request destination, reply destination = request source
        System.arraycopy(req.dstIp, 0, o, 12, 4);
        System.arraycopy(req.srcIp, 0, o, 16, 4);
        int csum = checksum(o, 0, 20);
        o[10] = (byte) (csum >> 8);
        o[11] = (byte) csum;

        o[20] = (byte) (req.dstPort >> 8);
        o[21] = (byte) req.dstPort;
        o[22] = (byte) (req.srcPort >> 8);
        o[23] = (byte) req.srcPort;
        int udpLen = 8 + payloadLen;
        o[24] = (byte) (udpLen >> 8);
        o[25] = (byte) udpLen;
        o[26] = 0; o[27] = 0;              // UDP checksum 0 = "not used" (allowed for IPv4)
        System.arraycopy(payload, 0, o, 28, payloadLen);
        return o;
    }

    static int checksum(byte[] b, int off, int len) {
        long sum = 0;
        for (int i = 0; i < len; i += 2) {
            int hi = b[off + i] & 0xFF;
            int lo = (i + 1 < len) ? (b[off + i + 1] & 0xFF) : 0;
            sum += (hi << 8) | lo;
        }
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum & 0xFFFF);
    }
}
