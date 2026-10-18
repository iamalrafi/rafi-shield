package bd.bettingshield.core;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Verifies that a downloaded blocklist was signed by the list maintainer (ECDSA P-256 / SHA-256).
 * This protects users if the hosting account or the network is tampered with.
 */
public final class ListSignature {

    private ListSignature() {}

    /**
     * @param data           the exact bytes of the list file
     * @param signatureBase64 DER signature, Base64 encoded
     * @param publicKeyBase64 X.509 (SubjectPublicKeyInfo) public key, Base64 encoded
     */
    public static boolean verify(byte[] data, String signatureBase64, String publicKeyBase64) {
        try {
            byte[] sig = Base64.getMimeDecoder().decode(signatureBase64.trim());
            byte[] key = Base64.getMimeDecoder().decode(publicKeyBase64.trim());
            PublicKey pk = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(key));
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initVerify(pk);
            s.update(data);
            return s.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }
}
