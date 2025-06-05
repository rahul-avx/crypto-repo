package my_java_lib;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import javax.crypto.Mac;

public class SmartHasher {
    public String computeMAC(String data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] macBytes = mac.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(macBytes);
    }

    public String computeHash(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] hash = digest.digest(input.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
}

