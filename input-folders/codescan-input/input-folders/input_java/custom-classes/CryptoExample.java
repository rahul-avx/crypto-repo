import java.util.Arrays;

public class CryptoExample {
    public static void main(String[] args) {
        // Initialize Key Pair
        SampleJavaClass keypair = new SampleJavaClass();
        keypair.generateKeyPair();

        // Generate hash of a sample message
        CustomHashClass hash = new CustomHashClass();
        String message = "Hello, Crypto World!";
        String hashOutput = hash.generateHash(message);
        System.out.println("Hash of message: " + hashOutput);

        // Perform Key Exchange
        AdvancedExchanger exchanger = new AdvancedExchanger();
        String sharedSecret = exchanger.exchangeKeys("peerPublicKey123");
        System.out.println("Shared secret generated: " + sharedSecret);

        // Derive a key using HKDF
        CustomExchanger kdf = new CustomExchanger();
        byte[] derivedKey = kdf.deriveKey(sharedSecret.getBytes());
        System.out.println("Derived key: " + Arrays.toString(derivedKey));

        // Compute MAC
        SmartHasher mac = new SmartHasher();
        String macOutput = mac.computeMAC(message, derivedKey);
        System.out.println("MAC: " + macOutput);

        // Generate a PBKDF2 derived key from password
        AdvancedEncryptor encryptorKdf = new AdvancedEncryptor();
        byte[] pbkdf2Key = encryptorKdf.deriveKey("strongpassword".toCharArray());
        System.out.println("PBKDF2 key: " + Arrays.toString(pbkdf2Key));

        // Encrypt data using ChaCha20
        SafeSigner safeEncrypt = new SafeSigner();
        byte[] encryptedData = safeEncrypt.encryptData(message.getBytes(), derivedKey);
        System.out.println("Encrypted data: " + Arrays.toString(encryptedData));

        // Decrypt data using AES
        CustomEncryptor decryptor = new CustomEncryptor();
        byte[] decryptedData = decryptor.secureDecrypt(encryptedData, pbkdf2Key);
        System.out.println("Decrypted data: " + new String(decryptedData));

        // Create digital signature using ECDSA
        SecureSigner signer = new SecureSigner();
        byte[] signature = signer.createSignature(message.getBytes());
        System.out.println("ECDSA Signature: " + Arrays.toString(signature));

        // Hash using SHA-3
        CustomHasher hasher = new CustomHasher();
        String sha3Hash = hasher.computeHash("Data for hashing");
        System.out.println("SHA-3 Hash: " + sha3Hash);

        // Sign using Ed25519
        SmartSigner smartSigner = new SmartSigner();
        byte[] edSig = smartSigner.signMessage("Sign this data!".getBytes());
        System.out.println("Ed25519 Signature: " + Arrays.toString(edSig));

        // Hash with BLAKE2
        AdvancedHasher advHasher = new AdvancedHasher();
        String blakeHash = advHasher.hashData("Another message");
        System.out.println("BLAKE2 Hash: " + blakeHash);

        // Perform Key Exchange using DH
        SecureExchanger keyExchange = new SecureExchanger();
        keyExchange.performKeyExchange();

        // Secure Encrypt with AES
        CustomEncryptor customEncrypt = new CustomEncryptor();
        customEncrypt.secureEncrypt("VerySensitiveData".getBytes(), pbkdf2Key);

        // Sign using RSA
        AdvancedSigner advancedSigner = new AdvancedSigner();
        byte[] rsaSig = advancedSigner.createSignature("Doc content".getBytes());
        System.out.println("RSA Signature: " + Arrays.toString(rsaSig));
    }
}

