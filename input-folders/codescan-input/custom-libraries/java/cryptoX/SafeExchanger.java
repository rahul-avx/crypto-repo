package cryptoX;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.Base64;

public class SafeExchanger {
    public KeyPair exchangeKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
}

