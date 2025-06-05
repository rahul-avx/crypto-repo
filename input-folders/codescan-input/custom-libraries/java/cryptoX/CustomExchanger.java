package cryptoX;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.Base64;

public class CustomExchanger {
    public SecretKey deriveKey(String sharedSecret) throws Exception {
        byte[] secretBytes = sharedSecret.getBytes();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha256.digest(secretBytes);
        return new javax.crypto.spec.SecretKeySpec(keyBytes, 0, 16, "AES");
    }
}

