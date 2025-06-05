package cryptoX;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.Base64;

public class AdvancedHasher {
    public String hashData(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("BLAKE2B-256");
        byte[] hash = digest.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
}

