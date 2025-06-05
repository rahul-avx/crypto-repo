package cryptoX;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.Base64;

public class SecureSigner {
    public byte[] createSignature(String message, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("SHA512withECDSA");
        signer.initSign(privateKey);
        signer.update(message.getBytes());
        return signer.sign();
    }
}

