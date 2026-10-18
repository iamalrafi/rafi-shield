package bd.bettingshield.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import org.junit.Test;

public class CoreTest {

    private static DomainMatcher matcherOf(String... domains) {
        DomainMatcher m = new DomainMatcher();
        Set<String> s = new HashSet<>();
        for (String d : domains) s.add(d);
        m.replace(s);
        return m;
    }

    // ---- matching ----

    @Test public void exactAndSubdomainsAreBlocked() {
        DomainMatcher m = matcherOf("example.com");
        assertEquals("example.com", m.match("example.com"));
        assertEquals("example.com", m.match("www.example.com"));
        assertEquals("example.com", m.match("a.b.c.example.com"));
        assertEquals("example.com", m.match("EXAMPLE.com."));
    }

    @Test public void lookalikeDomainsAreNotBlocked() {
        DomainMatcher m = matcherOf("example.com");
        assertNull(m.match("notexample.com"));
        assertNull(m.match("example.com.evil.org"));
        assertNull(m.match("example.org"));
        assertNull(m.match("com"));
        assertNull(m.match(""));
        assertNull(m.match(null));
    }

    @Test public void subdomainEntryDoesNotBlockParent() {
        DomainMatcher m = matcherOf("bet.example.com");
        assertEquals("bet.example.com", m.match("bet.example.com"));
        assertEquals("bet.example.com", m.match("x.bet.example.com"));
        assertNull(m.match("example.com"));
        assertNull(m.match("www.example.com"));
    }

    @Test public void protectedServicesNeverBlockedEvenIfListedByMistake() {
        DomainMatcher m = matcherOf("google.com", "youtube.com", "facebook.com", "bkash.com", "gov.bd");
        assertNull(m.match("www.google.com"));
        assertNull(m.match("m.youtube.com"));
        assertNull(m.match("facebook.com"));
        assertNull(m.match("app.bkash.com"));
        assertNull(m.match("nbr.gov.bd"));
    }

    // ---- list parsing ----

    @Test public void parserAcceptsPlainAndHostsFormat() throws Exception {
        String text = "# comment\n"
                + "\n"
                + "bettingnb.com\n"
                + "0.0.0.0 melbet.example\n"
                + "127.0.0.1 another-bet.net  # trailing comment\n"
                + "Mixed.CASE.org\n"
                + "dup.com\ndup.com\n";
        DomainMatcher.Parsed p = DomainMatcher.parse(
                new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)));
        assertTrue(p.domains.contains("bettingnb.com"));
        assertTrue(p.domains.contains("melbet.example"));
        assertTrue(p.domains.contains("another-bet.net"));
        assertTrue(p.domains.contains("mixed.case.org"));
        assertEquals(5, p.domains.size()); // duplicates collapsed
        assertEquals(0, p.rejectedLines);
    }

    @Test public void parserRejectsUnsafeEntries() throws Exception {
        String text = "*.example.com\n"
                + "http://example.com/path\n"
                + "example.com:8080\n"
                + "localhost\n"
                + "1.2.3.4\n"
                + "-bad-.com\n"
                + "two words here\n"
                + "com.bd\n"
                + "google.com\n"
                + "good-bet.com\n";
        DomainMatcher.Parsed p = DomainMatcher.parse(
                new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)));
        assertEquals(1, p.domains.size());
        assertTrue(p.domains.contains("good-bet.com"));
        assertTrue(p.rejectedLines >= 6);
        assertEquals(2, p.protectedSkipped); // com.bd and google.com
    }

    // ---- URL normalisation (used by the "report" screen) ----

    @Test public void normalizeHostCleansUrls() {
        assertEquals("bettingnb.com", DomainUtil.normalizeHost("bettingnb.com"));
        assertEquals("www.example.com", DomainUtil.normalizeHost("  HTTPS://WWW.Example.com:8080/a/b?x=1#f "));
        assertEquals("example.com", DomainUtil.normalizeHost("user:pw@example.com/"));
        assertEquals("example.com", DomainUtil.normalizeHost("example.com."));
        assertEquals("xn--bcher-kva.example", DomainUtil.normalizeHost("bücher.example"));
    }

    @Test public void normalizeHostRejectsInvalidInput() {
        assertNull(DomainUtil.normalizeHost(null));
        assertNull(DomainUtil.normalizeHost(""));
        assertNull(DomainUtil.normalizeHost("localhost"));
        assertNull(DomainUtil.normalizeHost("192.168.0.1"));
        assertNull(DomainUtil.normalizeHost("http://[::1]/"));
        assertNull(DomainUtil.normalizeHost("exa mple.com"));
        assertNull(DomainUtil.normalizeHost("example..com"));
        assertNull(DomainUtil.normalizeHost("example.com:abc"));
        assertNull(DomainUtil.normalizeHost("javascript:alert(1)"));
    }

    @Test public void blockableRules() {
        assertTrue(DomainUtil.isBlockable("bettingnb.com"));
        assertFalse(DomainUtil.isBlockable("www.google.com"));
        assertFalse(DomainUtil.isBlockable("com.bd"));
        assertFalse(DomainUtil.isBlockable("sub.bkash.com"));
        assertFalse(DomainUtil.isBlockable("x"));
    }

    // ---- DNS + IP packets ----

    private static byte[] dnsQuery(String name, int qtype) {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        o.write(0x12); o.write(0x34);       // id
        o.write(0x01); o.write(0x00);       // flags: RD
        o.write(0); o.write(1);             // QDCOUNT
        o.write(0); o.write(0); o.write(0); o.write(0); o.write(0); o.write(0);
        for (String label : name.split("\\.")) {
            o.write(label.length());
            byte[] b = label.getBytes(StandardCharsets.US_ASCII);
            o.write(b, 0, b.length);
        }
        o.write(0);
        o.write(qtype >> 8); o.write(qtype & 0xFF);
        o.write(0); o.write(1);             // class IN
        return o.toByteArray();
    }

    @Test public void dnsQuestionIsParsed() {
        byte[] q = dnsQuery("Www.BettingNB.com", 1);
        DnsMessage.Question question = DnsMessage.parseQuestion(q, 0, q.length);
        assertNotNull(question);
        assertEquals("www.bettingnb.com", question.name);
        assertEquals(1, question.type);
        assertEquals(q.length, question.endOffset);
    }

    @Test public void malformedDnsIsIgnored() {
        assertNull(DnsMessage.parseQuestion(new byte[5], 0, 5));
        byte[] q = dnsQuery("example.com", 1);
        assertNull(DnsMessage.parseQuestion(q, 0, q.length - 3));   // truncated
        q[2] = (byte) 0x81;                                         // looks like a response
        assertNull(DnsMessage.parseQuestion(q, 0, q.length));
    }

    @Test public void blockedResponseIsNxdomainWithSameId() {
        byte[] q = dnsQuery("bettingnb.com", 28);
        DnsMessage.Question question = DnsMessage.parseQuestion(q, 0, q.length);
        byte[] r = DnsMessage.buildBlockedResponse(q, 0, q.length, question);
        assertEquals(q.length, r.length);
        assertEquals(0x12, r[0] & 0xFF);
        assertEquals(0x34, r[1] & 0xFF);
        assertTrue((r[2] & 0x80) != 0);          // QR = response
        assertEquals(1, r[2] & 0x01);            // RD copied
        assertEquals(3, r[3] & 0x0F);            // RCODE = NXDOMAIN
        assertEquals(0, r[6]); assertEquals(0, r[7]); // ANCOUNT 0
    }

    @Test public void ipv4UdpRoundTrip() {
        byte[] dns = dnsQuery("example.com", 1);
        int total = 20 + 8 + dns.length;
        byte[] pkt = new byte[total];
        pkt[0] = 0x45;
        pkt[2] = (byte) (total >> 8); pkt[3] = (byte) total;
        pkt[8] = 64; pkt[9] = 17;
        byte[] src = {10, 0, 0, 2}, dst = {10, 0, 0, 1};
        System.arraycopy(src, 0, pkt, 12, 4);
        System.arraycopy(dst, 0, pkt, 16, 4);
        pkt[20] = (byte) 0xC3; pkt[21] = (byte) 0x50;   // src port 50000
        pkt[22] = 0; pkt[23] = 53;                      // dst port 53
        int udpLen = 8 + dns.length;
        pkt[24] = (byte) (udpLen >> 8); pkt[25] = (byte) udpLen;
        System.arraycopy(dns, 0, pkt, 28, dns.length);

        Ipv4Udp.Packet p = Ipv4Udp.parse(pkt, pkt.length);
        assertNotNull(p);
        assertEquals(50000, p.srcPort);
        assertEquals(53, p.dstPort);
        assertEquals(28, p.payloadOffset);
        assertEquals(dns.length, p.payloadLength);
        assertArrayEquals(src, p.srcIp);

        byte[] reply = Ipv4Udp.buildReply(p, dns, dns.length);
        Ipv4Udp.Packet rp = Ipv4Udp.parse(reply, reply.length);
        assertNotNull(rp);
        assertArrayEquals(dst, rp.srcIp);          // swapped
        assertArrayEquals(src, rp.dstIp);
        assertEquals(53, rp.srcPort);
        assertEquals(50000, rp.dstPort);
        assertEquals(0, Ipv4Udp.checksum(reply, 0, 20)); // header checksum is valid
    }

    @Test public void nonUdpOrTcpPacketsAreIgnored() {
        byte[] pkt = new byte[40];
        pkt[0] = 0x45; pkt[3] = 40; pkt[9] = 6; // TCP
        assertNull(Ipv4Udp.parse(pkt, 40));
        pkt[0] = 0x60;                           // IPv6
        assertNull(Ipv4Udp.parse(pkt, 40));
    }

    // ---- signature ----

    @Test public void signatureVerification() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(256);
        KeyPair kp = g.generateKeyPair();
        byte[] data = "a.com\nb.com\n".getBytes(StandardCharsets.UTF_8);
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(kp.getPrivate());
        s.update(data);
        String sig = Base64.getEncoder().encodeToString(s.sign());
        String pub = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());

        assertTrue(ListSignature.verify(data, sig, pub));
        byte[] tampered = "a.com\nb.com\nevil.com\n".getBytes(StandardCharsets.UTF_8);
        assertFalse(ListSignature.verify(tampered, sig, pub));
        assertFalse(ListSignature.verify(data, "AAAA", pub));
        assertFalse(ListSignature.verify(data, sig, "not-a-key"));
    }
}
