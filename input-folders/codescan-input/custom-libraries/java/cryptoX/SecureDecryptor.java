package cryptoX;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class SecureDecryptor {
    public String decryptData(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(encryptedData);
        return new String(decrypted);
    }
}

