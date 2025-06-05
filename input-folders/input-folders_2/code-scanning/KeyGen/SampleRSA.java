import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class RSAKeyExample {
    public static void main(String[] args) {
        try {
            // Initialize the RSA key pair generator
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // Key size

            // Generate the key pair
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            // Print the keys
            System.out.println("RSA Public Key: " + publicKey);
            System.out.println("RSA Private Key: " + privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

