import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;

public class AESCFBNoPaddingExample {
    public static void main(String[] args) throws Exception {
        // Generate AES key (128-bit for demo, can use 192/256 if policy allows)
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();

        // Generate random IV (AES block size = 16 bytes)
        byte[] iv = new byte[16];
        java.security.SecureRandom random = new java.security.SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Create Cipher for AES/CFB/NoPadding
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");

        // Plaintext
        String plaintext = "Hello, AES CFB Mode with NoPadding!";
        byte[] plainBytes = plaintext.getBytes();

        // Encryption
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] cipherText = cipher.doFinal(plainBytes);

        System.out.println("Original: " + plaintext);
        System.out.println("Encrypted (hex): " + bytesToHex(cipherText));

        // Decryption
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decrypted = cipher.doFinal(cipherText);
        System.out.println("Decrypted: " + new String(decrypted));
    }

    // Utility function to print bytes in hex
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
