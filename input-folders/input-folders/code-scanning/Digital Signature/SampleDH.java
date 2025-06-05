import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class DHKeyExample {
    public static void main(String[] args) {
        try {
            // Define DH parameters (default for example purposes)
            int primeSize = 2048;

            // Initialize the DH key pair generator
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(primeSize);

            // Generate the key pair
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
            DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();

            // Print the keys
            System.out.println("DH Public Key: " + publicKey);
            System.out.println("DH Private Key: " + privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

