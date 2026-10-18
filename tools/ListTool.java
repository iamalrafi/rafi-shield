import bd.bettingshield.core.DomainMatcher;
import bd.bettingshield.core.DomainUtil;
import bd.bettingshield.core.ListSignature;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

/**
 * Maintenance tool for the shared blocklist. Used by the GitHub Actions workflow, but can also be run by hand:
 *
 *   genkey <folder>                      create a signing key pair (keep private.key SECRET)
 *   build  <out> <allow-file> <in...>    merge lists, drop unsafe/protected entries and allowed (fixed) entries
 *   sign   <file>                        sign <file> using the key in env BS_PRIVATE_KEY, write <file>.sig
 *   verify <file> <public-key-file>      check <file>.sig
 *
 * Compile together with the app's core classes (see .github/workflows/blocklist.yml).
 */
public class ListTool {

    public static void main(String[] a) throws Exception {
        if (a.length == 0) usage();
        switch (a[0]) {
            case "genkey": genkey(a[1]); break;
            case "build": build(a); break;
            case "sign": sign(a[1]); break;
            case "verify": verify(a[1], a[2]); break;
            default: usage();
        }
    }

    static void usage() {
        System.err.println("usage: genkey <dir> | build <out> <allow> <in...> | sign <file> | verify <file> <pubkey>");
        System.exit(2);
    }

    static void genkey(String dir) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(256);
        KeyPair kp = g.generateKeyPair();
        Files.createDirectories(Path.of(dir));
        Files.writeString(Path.of(dir, "private.key"), Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()));
        Files.writeString(Path.of(dir, "public.key"), Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));
        System.out.println("wrote " + dir + "/private.key (SECRET) and " + dir + "/public.key");
    }

    static void build(String[] a) throws Exception {
        String out = a[1];
        Set<String> allow = new HashSet<>();
        File allowFile = new File(a[2]);
        if (allowFile.exists()) {
            try (FileInputStream in = new FileInputStream(allowFile)) {
                allow = DomainMatcher.parse(in).domains;
            }
        }
        TreeSet<String> all = new TreeSet<>();
        for (int i = 3; i < a.length; i++) {
            File f = new File(a[i]);
            if (!f.exists()) {
                System.err.println("skip missing " + a[i]);
                continue;
            }
            try (FileInputStream in = new FileInputStream(f)) {
                DomainMatcher.Parsed p = DomainMatcher.parse(in);
                all.addAll(p.domains);
                System.out.println(a[i] + ": " + p.domains.size() + " valid, " + p.rejectedLines
                        + " rejected, " + p.protectedSkipped + " protected/too broad skipped");
            }
        }
        int removed = 0;
        for (String d : allow) {
            if (all.remove(d)) removed++;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("# Betting Shield BD blocklist (generated - edit blocklist/manual.txt or allow.txt instead)\n");
        sb.append("# entries: ").append(all.size()).append('\n');
        for (String d : all) {
            if (!DomainUtil.isBlockable(d)) continue; // belt and braces
            sb.append(d).append('\n');
        }
        Files.writeString(Path.of(out), sb.toString(), StandardCharsets.UTF_8);
        System.out.println("wrote " + out + ": " + all.size() + " domains (" + removed + " removed by allow list)");
        if (all.isEmpty()) {
            System.err.println("refusing: result is empty");
            System.exit(1);
        }
    }

    static void sign(String file) throws Exception {
        String key = System.getenv("BS_PRIVATE_KEY");
        if (key == null || key.isBlank()) {
            System.err.println("BS_PRIVATE_KEY is not set");
            System.exit(1);
        }
        PrivateKey pk = KeyFactory.getInstance("EC")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(key.trim())));
        byte[] data = Files.readAllBytes(Path.of(file));
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(pk);
        s.update(data);
        Files.writeString(Path.of(file + ".sig"), Base64.getEncoder().encodeToString(s.sign()) + "\n");
        System.out.println("signed " + file);
    }

    static void verify(String file, String pubFile) throws Exception {
        byte[] data = Files.readAllBytes(Path.of(file));
        String sig = Files.readString(Path.of(file + ".sig"));
        String pub = Files.readString(Path.of(pubFile));
        boolean ok = ListSignature.verify(data, sig, pub);
        System.out.println(ok ? "signature OK" : "signature INVALID");
        System.exit(ok ? 0 : 1);
    }
}
