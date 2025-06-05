package my_java_lib;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import javax.crypto.Mac;


public class CustomHashClass {
    public String generateHash(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
}

