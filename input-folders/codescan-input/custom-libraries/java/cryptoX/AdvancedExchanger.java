package cryptoX;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.Base64;

public class AdvancedExchanger {
    public byte[] exchangeKeys(KeyPair ownKeyPair, PublicKey peerPublicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(ownKeyPair.getPrivate());
        keyAgreement.doPhase(peerPublicKey, true);
        return keyAgreement.generateSecret();
    }
}


