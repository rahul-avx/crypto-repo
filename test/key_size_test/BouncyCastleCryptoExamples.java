package com.example.crypto;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BouncyCastleCryptoExamples {

    // Constants for key sizes
    private static final int AES_KEY_SIZE = 256;
    private static final int RSA_KEY_SIZE = 2048;
    private static final int ECC_KEY_SIZE = 256;  // NIST P-256
    private static final int DSA_KEY_SIZE = 2048;
    private static final int DH_KEY_SIZE = 2048;
    private static final int HMAC_KEY_SIZE = 256;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
     

    // RSA Key Generation
    public static KeyPair generateRSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize("2048");
        return keyGen.generateKeyPair();
    }

    // AES Key Generation using KeyGenerator
    public static SecretKey generateAESKey(int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    // AES Encryption
    public static byte[] encryptAES(byte[] plaintext, SecretKey key, int ivSize) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(plaintext);
    }

    // ECC Key Generation (e.g., P-256)
    public static KeyPair generateECCKeyPair(int curveBits) throws Exception {
        String curveName = "P-256"; // keySize = 256
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(ecSpec, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    // DSA Key Generation
    public static KeyPair generateDSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "BC");
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    // DH Key Generation
    public static KeyPair generateDHKeyPair(int keySize) throws Exception {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH", "BC");
        paramGen.init(keySize);
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
        keyGen.initialize(dhSpec);
        return keyGen.generateKeyPair();
    }

    // HMAC key generation and calculation
    public static byte[] generateHMAC(byte[] data, int keySizeBits) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256", "BC");
        keyGen.init(keySizeBits); // e.g., 256 bits
        SecretKey key = keyGen.generateKey();

        Mac hmac = Mac.getInstance("HmacSHA256", "BC");
        hmac.init(key);
        return hmac.doFinal(data);
    }

    // Example usage
    public static void main(String[] args) throws Exception {
    	
    	for(int i=0;i<1;i++){
    	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(keySize);
        }
    
        KeyPair rsaKey = generateRSAKeyPair("2048");
        SecretKey aesKey = generateAESKey(AES_KEY_SIZE);
        KeyPair eccKey = generateECCKeyPair(ECC_KEY_SIZE);
        KeyPair dsaKey = generateDSAKeyPair(DSA_KEY_SIZE);
        KeyPair dhKey = generateDHKeyPair(DH_KEY_SIZE);

        byte[] data = "Hello Bouncy Castle!".getBytes();
        byte[] ciphertext = encryptAES(data, aesKey, 16);
        byte[] hmac = generateHMAC(data, HMAC_KEY_SIZE);

        System.out.println("Encryption and HMAC done using Bouncy Castle!");
    }
}
