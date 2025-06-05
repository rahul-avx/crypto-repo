package my_java_lib;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import javax.crypto.Mac;


public class SmartKDF {
    public SecretKey generateDerivedKey(String password) throws Exception {
        byte[] keyBytes = password.getBytes();
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        keyBytes = sha.digest(keyBytes);
        return new SecretKeySpec(keyBytes, 0, 16, "AES");
    }
}

