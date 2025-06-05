import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import java.security.*;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class BouncyCastleExample {

    public static void main(String[] args) throws Exception {
        // Add Bouncy Castle as a Security Provider
        Security.addProvider(new BouncyCastleProvider());

        // Generate RSA key pair using Bouncy Castle
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Extract public and private keys
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Convert keys to Bouncy Castle AsymmetricKeyParameter
        AsymmetricKeyParameter publicKeyParameter = PublicKeyFactory.createKey(publicKey.getEncoded());
        AsymmetricKeyParameter privateKeyParameter = PrivateKeyFactory.createKey(privateKey.getEncoded());

        // Message to be encrypted
        String message = "Hello, Bouncy Castle!";

        // Encrypt the message using RSA and PKCS1 padding
        byte[] encryptedMessage = encrypt(publicKeyParameter, message.getBytes());

        System.out.println("Encrypted Message: " + Hex.toHexString(encryptedMessage));

        // Decrypt the message
        byte[] decryptedMessage = decrypt(privateKeyParameter, encryptedMessage);

        System.out.println("Decrypted Message: " + new String(decryptedMessage));
    }

    public static byte[] encrypt(AsymmetricKeyParameter publicKey, byte[] inputData) throws Exception {
        AsymmetricBlockCipher cipher = new PKCS1Encoding(new RSAEngine());
        cipher.init(true, publicKey); // true = encrypt
        return cipher.processBlock(inputData, 0, inputData.length);
    }

    public static byte[] decrypt(AsymmetricKeyParameter privateKey, byte[] inputData) throws Exception {
        AsymmetricBlockCipher cipher = new PKCS1Encoding(new RSAEngine());
        cipher.init(false, privateKey); // false = decrypt
        return cipher.processBlock(inputData, 0, inputData.length);
    }
}
