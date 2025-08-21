import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class KeyPairGeneratorExample {
    public static void main(String[] args) {
        try {
            // Use the constant from CryptoConfig
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(CryptoConfig.RSA_KEY_SIZE);

            // Generate the key pair
            KeyPair keyPair = keyGen.generateKeyPair();

            System.out.println("RSA Key Pair generated successfully!");
            System.out.println("Public Key Algorithm: " + keyPair.getPublic().getAlgorithm());
            System.out.println("Key Size: " + CryptoConfig.RSA_KEY_SIZE);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
