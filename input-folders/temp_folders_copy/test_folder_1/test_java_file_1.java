// package input_files.test_folder_1;

// import java.security.*;
// public class test_java_file_1 {
//     public static void main(String[] args) {
//         try {
//             KeyPairGenerator pqcKeyGen = KeyPairGenerator.getInstance("SPHINCSPlus");
//             pqcKeyGen.initialize(256);
//             KeyPair pqcKeyPair = pqcKeyGen.generateKeyPair();
//             Signature pqcSignature = Signature.getInstance("SPHINCSPlus");
//             pqcSignature.initSign(pqcKeyPair.getPrivate());
//             pqcSignature.update("Hello, World!".getBytes());
//         }
//         catch (Exception e) {
//         }
//     }

//     public static void function() {
//         try {
//             KeyPairGenerator pqcKeyGen = KeyPairGenerator.getInstance("SPHINCSPlus");
//             pqcKeyGen.initialize(256);
//             KeyPair pqcKeyPair = pqcKeyGen.generateKeyPair();
//             Signature pqcSignature = Signature.getInstance("SPHINCSPlus");
//             pqcSignature.initSign(pqcKeyPair.getPrivate());
//             pqcSignature.update("Hello, World!".getBytes());
//         }
//         catch (Exception e) {
//         }
//     }
// }

// class Cipher {
//     int i;
//     char c;
//     static String sphincs = "SPHINCSPlus";
//     public static void func() {
//         System.out.println();
//         try {
//             KeyPairGenerator pqcKeyGen = KeyPairGenerator.getInstance(sphincs);
//             pqcKeyGen.initialize(256);
//             KeyPair pqcKeyPair = pqcKeyGen.generateKeyPair();
//             Signature pqcSignature = Signature.getInstance(sphincs);
//             pqcSignature.initSign(pqcKeyPair.getPrivate());
//             pqcSignature.update("Hello, World!".getBytes());
//         }
//         catch (Exception e) {
//         }
//     }
// }