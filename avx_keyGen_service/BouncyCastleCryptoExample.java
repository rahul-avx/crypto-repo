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

public class BouncyCastleCryptoExample {

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
    
    

    // Example usage
    public static void main(String[] args) throws Exception {
    	
    	int keySize = 2048;
    	int key_size = keySize;
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(key_size);
    
    }
}
