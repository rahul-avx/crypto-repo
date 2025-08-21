import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import com.github.jponge.blake3.Blake3;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.List;

public class AllHashesExample {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        byte[] data = "Hash this message with all algorithms!".getBytes(StandardCharsets.UTF_8);

        // JCA / standard hashes
        List<String> jcaHashes = Arrays.asList("MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512");
        for (String algo : jcaHashes) {	
        	
            MessageDigest md = MessageDigest.getInstance(algo);
            byte[] digest = md.digest(data);
            System.out.printf("%-10s : %s%n", algo, toHex(digest));
        }

    }
}
