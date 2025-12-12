import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class AsymmetricCryptoToolkit {

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    public static void main(String[] args) throws Exception {
        String message = "Asymmetric Crypto Toolkit Test";
        byte[] data = message.getBytes();

        System.out.println("Message: " + message + "\n");

        // 1. RSA
        runRSA(1024, data);
        runRSA(2048, data);
        runRSA(3072, data);
        runRSA(4096, data);

        // 2. DH
        runDH(2048);
        runDH(3072);

        // 3. ECDSA/ECDH
        runECDSA("P-256", data);
        runECDSA("P-384", data);
        runECDH("P-256");
        runECDH("P-384");

        // 4. EdDSA / XDH
        runEdDSA(data);
        runXDH();

        // 5. ElGamal
        runElGamal(data);

        // 6. PQC examples
        runKyber();
        runDilithium(data);
        runFalcon(data);
        runSPHINCS(data);
        runMcEliece();
        runSIKE();
        runLMS_XMSS(data);

        // 7. Hybrid RSA+Kyber
        runHybridRSA_Kyber(data);
    }

    /** RSA encryption/decryption demo */
    private static void runRSA(int keySize, byte[] data) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(keySize);
        KeyPair kp = kpg.generateKeyPair();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] encrypted = cipher.doFinal(data);

        cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] decrypted = cipher.doFinal(encrypted);

        System.out.printf("RSA-%d Decrypted: %s%n", keySize, new String(decrypted));
    }

    /** Diffie-Hellman key agreement */
    private static void runDH(int keySize) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "BC");
        kpg.initialize(keySize);
        KeyPair kp1 = kpg.generateKeyPair();
        KeyPair kp2 = kpg.generateKeyPair();

        KeyAgreement ka1 = KeyAgreement.getInstance("DH", "BC");
        ka1.init(kp1.getPrivate());
        ka1.doPhase(kp2.getPublic(), true);
        byte[] secret1 = ka1.generateSecret();

        KeyAgreement ka2 = KeyAgreement.getInstance("DH", "BC");
        ka2.init(kp2.getPrivate());
        ka2.doPhase(kp1.getPublic(), true);
        byte[] secret2 = ka2.generateSecret();

        System.out.printf("DH-%d Secret Match: %b%n", keySize, Arrays.equals(secret1, secret2));
    }

    /** ECDSA signing/verification */
    private static void runECDSA(String curve, byte[] data) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec(curve));
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withECDSA", "BC");
        sig.initSign(kp.getPrivate());
        sig.update(data);
        byte[] signature = sig.sign();

        sig.initVerify(kp.getPublic());
        sig.update(data);
        boolean valid = sig.verify(signature);
        System.out.printf("ECDSA-%s Signature valid: %b%n", curve, valid);
    }

    /** ECDH key agreement */
    private static void runECDH(String curve) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec(curve));
        KeyPair kp1 = kpg.generateKeyPair();
        KeyPair kp2 = kpg.generateKeyPair();

        KeyAgreement ka1 = KeyAgreement.getInstance("ECDH", "BC");
        ka1.init(kp1.getPrivate());
        ka1.doPhase(kp2.getPublic(), true);
        byte[] secret1 = ka1.generateSecret();

        KeyAgreement ka2 = KeyAgreement.getInstance("ECDH", "BC");
        ka2.init(kp2.getPrivate());
        ka2.doPhase(kp1.getPublic(), true);
        byte[] secret2 = ka2.generateSecret();

        System.out.printf("ECDH-%s Secret Match: %b%n", curve, Arrays.equals(secret1, secret2));
    }

    /** Ed25519 signing/verification */
    private static void runEdDSA(byte[] data) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Ed25519", "BC");
        sig.initSign(kp.getPrivate());
        sig.update(data);
        byte[] signature = sig.sign();

        sig.initVerify(kp.getPublic());
        sig.update(data);
        boolean valid = sig.verify(signature);
        System.out.printf("Ed25519 Signature valid: %b%n", valid);
    }

    /** X25519 key agreement */
    private static void runXDH() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "BC");
        KeyPair kp1 = kpg.generateKeyPair();
        KeyPair kp2 = kpg.generateKeyPair();

        KeyAgreement ka1 = KeyAgreement.getInstance("X25519", "BC");
        ka1.init(kp1.getPrivate());
        ka1.doPhase(kp2.getPublic(), true);
        byte[] secret1 = ka1.generateSecret();

        KeyAgreement ka2 = KeyAgreement.getInstance("X25519", "BC");
        ka2.init(kp2.getPrivate());
        ka2.doPhase(kp1.getPublic(), true);
        byte[] secret2 = ka2.generateSecret();

        System.out.printf("X25519 Secret Match: %b%n", Arrays.equals(secret1, secret2));
    }

    /** ElGamal (example encryption/decryption) */
    private static void runElGamal(byte[] data) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ElGamal", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        Cipher cipher = Cipher.getInstance("ElGamal/None/PKCS1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] encrypted = cipher.doFinal(data);

        cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] decrypted = cipher.doFinal(encrypted);
        System.out.printf("ElGamal Decrypted: %s%n", new String(decrypted));
    }

    /** PQC Key encapsulation / signature stubs (examples) */
    private static void runKyber() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber512", "BCPQC");
        KeyPair kp = kpg.generateKeyPair();
        System.out.println("Kyber512 keypair generated.\n");
    }

    private static void runDilithium(byte[] data) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium2", "BCPQC");
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Dilithium2", "BCPQC");
        sig.initSign(kp.getPrivate());
        sig.update(data);
        byte[] signature = sig.sign();

        sig.initVerify(kp.getPublic());
        sig.update(data);
        boolean valid = sig.verify(signature);
        System.out.printf("Dilithium2 Signature valid: %b%n", valid);
    }

    private static void runFalcon(byte[] data) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Falcon-512", "BCPQC");
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Falcon-512", "BCPQC");
        sig.initSign(kp.getPrivate());
        sig.update(data);
        byte[] signature = sig.sign();

        sig.initVerify(kp.getPublic());
        sig.update(data);
        boolean valid = sig.verify(signature);
        System.out.printf("Falcon-512 Signature valid: %b%n", valid);
    }

    private static void runSPHINCS(byte[] data) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SPHINCSPlus", "BCPQC");
        sig.initSign(kp.getPrivate());
        sig.update(data);
        byte[] signature = sig.sign();

        sig.initVerify(kp.getPublic());
        sig.update(data);
        boolean valid = sig.verify(signature);
        System.out.printf("SPHINCS+ Signature valid: %b%n", valid);
    }

    private static void runMcEliece() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("McEliece", "BCPQC");
        KeyPair kp = kpg.generateKeyPair();
        System.out.println("McEliece keypair generated.\n");
    }

    private static void runSIKE() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SIKEp503", "BCPQC");
        KeyPair kp = kpg.generateKeyPair();
        System.out.println("SIKEp503 keypair generated.\n");
    }

    private static void runLMS_XMSS(byte[] data) throws Exception {
        KeyPairGenerator kpgLMS = KeyPairGenerator.getInstance("LMS", "BCPQC");
        KeyPair kpLMS = kpgLMS.generateKeyPair();
        System.out.println("LMS keypair generated.\n");

        KeyPairGenerator kpgXMSS = KeyPairGenerator.getInstance("XMSS", "BCPQC");
        KeyPair kpXMSS = kpgXMSS.generateKeyPair();
        System.out.println("XMSS keypair generated.\n");
    }

    /** Hybrid: RSA + Kyber encapsulation stub */
    private static void runHybridRSA_Kyber(byte[] data) throws Exception {
        // Generate RSA
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", "BC");
        rsaKpg.initialize(2048);
        KeyPair rsaKp = rsaKpg.generateKeyPair();

        // Generate Kyber
        KeyPairGenerator kyberKpg = KeyPairGenerator.getInstance("Kyber512", "BCPQC");
        KeyPair kyberKp = kyberKpg.generateKeyPair();

        System.out.println("Hybrid RSA+Kyber keypairs generated.\n");
    }
}
