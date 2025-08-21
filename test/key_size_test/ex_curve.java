import java.security.*;
import java.security.spec.*;
import javax.crypto.KeyAgreement;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

// Bouncy Castle
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECKeyGenExample {

    // Constants
    private static final String CURVE_NAME_CONST = "secp384r1";

    public static void main(String[] args) throws Exception {
        // Add Bouncy Castle Provider
        Security.addProvider(new BouncyCastleProvider());

        // === 1. Using constant with Bouncy Castle ===
        String curveFromConst = CURVE_NAME_CONST;
        ECParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec(curveFromConst);
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("EC", "BC");
        bcKpg.initialize(bcSpec);
        KeyPair bcKeyPair = bcKpg.generateKeyPair();

        System.out.println("[BC] Generated key with curve: " + curveFromConst);

        // === 2. Directly passing string literal to ECGenParameterSpec ===
        KeyPairGenerator stdKpg = KeyPairGenerator.getInstance("EC");
        stdKpg.initialize(new ECGenParameterSpec("secp256r1")); // aka prime256v1
        KeyPair stdKeyPair = stdKpg.generateKeyPair();

        System.out.println("[Java] Generated key with curve: secp256r1");

        // === 3. Using variable holding curve name ===
        String dynamicCurve = "secp521r1";
        ECGenParameterSpec dynamicSpec = new ECGenParameterSpec(dynamicCurve);
        KeyPairGenerator dynamicKpg = KeyPairGenerator.getInstance("EC");
        dynamicKpg.initialize(dynamicSpec);
        KeyPair dynamicKeyPair = dynamicKpg.generateKeyPair();

        System.out.println("[Java] Generated key with curve: " + dynamicCurve);
    }
}
