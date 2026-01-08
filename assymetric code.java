import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class AsymmetricCryptoExtended {

    private static final String PLAINTEXT = "This is a test message for asymmetric crypto.";

    // Algorithm + Key Size matrix
    private static final Object[][] ALGORITHMS = {
            {"RSA", 2048},
            {"RSA", 4096},
            {"DSA", 2048},
            {"EC", 256},        // ECDSA over P-256
            {"Ed25519", -1},    // EdDSA
            {"Ed448", -1}       // EdDSA
    };

    public static void main(String[] args) throws Exception {
        // Register BC provider
        Security.addProvider(new BouncyCastleProvider());

        for (Object[] algoSpec : ALGORITHMS) {
            String algorithm = (String) algoSpec[0];
            int keySize = (int) algoSpec[1];
            try {
                runAsymmetricDemo(algorithm, keySize);
            } catch (Exception e) {
                System.out.println("⚠ Skipped unsupported: " + algorithm + " (" + e.getMessage() + ")");
            }
        }
    }

    private static void runAsymmetricDemo(String algorithm, int keySize) throws Exception {
        System.out.println("\n=== " + algorithm + (keySize > 0 ? " " + keySize : "") + " ===");

        // Generate key pair
        KeyPairGenerator keyGen;
        if (algorithm.startsWith("Ed")) {
            keyGen = KeyPairGenerator.getInstance(algorithm, "BC");
        } else if (algorithm.equals("EC")) {
            keyGen = KeyPairGenerator.getInstance("EC", "BC");
            keyGen.initialize(keySize);
        } else {
            keyGen = KeyPairGenerator.getInstance(algorithm, "BC");
            if (keySize > 0) keyGen.initialize(keySize);
        }

        KeyPair keyPair = keyGen.generateKeyPair();

        // Encryption / Decryption (only for RSA)
        if (algorithm.equalsIgnoreCase("RSA")) {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] cipherText = cipher.doFinal(PLAINTEXT.getBytes());
            String enc = Base64.getEncoder().encodeToString(cipherText);
            System.out.println("Encrypted (RSA): " + enc);

            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] decrypted = cipher.doFinal(cipherText);
            System.out.println("Decrypted (RSA): " + new String(decrypted));
        } else {
            System.out.println("Encryption skipped (unsupported for " + algorithm + ")");
        }

        // Signing
        String signatureAlgorithm = getSignatureAlgorithm(algorithm);
        Signature signature = Signature.getInstance(signatureAlgorithm, "BC");
        signature.initSign(keyPair.getPrivate());
        signature.update(PLAINTEXT.getBytes());
        byte[] sigBytes = signature.sign();
        String sigB64 = Base64.getEncoder().encodeToString(sigBytes);
        System.out.println("Signature (" + signatureAlgorithm + "): " + sigB64);

        // Verification
        Signature verifier = Signature.getInstance(signatureAlgorithm, "BC");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(PLAINTEXT.getBytes());
        boolean verified = verifier.verify(sigBytes);
        System.out.println("Signature Verified: " + verified);
    }

    private static String getSignatureAlgorithm(String algorithm) {
        return switch (algorithm) {
            case "RSA" -> "SHA256withRSA";
            case "DSA" -> "SHA256withDSA";
            case "EC" -> "SHA256withECDSA";
            case "Ed25519" -> "Ed25519"; // No hash needed, it's built-in
            case "Ed448" -> "Ed448";
            default -> throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
        };
    }
}
