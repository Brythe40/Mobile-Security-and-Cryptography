import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class Main {

    public static void main(String[] args) {
        String secretKey = "secretsecretsecr";
        byte[] key = secretKey.getBytes();
        HexFormat formatHexPrint = HexFormat.ofDelimiter(" ").withUpperCase();
        AES aes = new AES();

        String plaintext1 = "matrix";
        System.out.println("Plaintext: " + plaintext1);
        byte[] p1 = plaintext1.getBytes();

        byte[] encryptedP1 = aes.encrypt(key, p1);
        System.out.println("Encrypted Data:");
        System.out.println(formatHexPrint.formatHex(encryptedP1));

        byte[] decryptedP1 = aes.decrypt(key, encryptedP1);
        System.out.println("Decrypted Data:");
        System.out.println(formatHexPrint.formatHex(decryptedP1));
        System.out.println(new String(decryptedP1, StandardCharsets.UTF_8));

        String plaintext2 = "AES USES A MATRIX";
        System.out.println("\nPlaintext: " + plaintext2);
        byte[] p2 = plaintext2.getBytes();

        byte[] encryptedP2 = aes.encrypt(key, p2);
        System.out.println("Encrypted Data:");
        System.out.println(formatHexPrint.formatHex(encryptedP2));

        byte[] decryptedP2 = aes.decrypt(key, encryptedP2);
        System.out.println("Decrypted Data:");
        System.out.println(formatHexPrint.formatHex(decryptedP2));
        System.out.println(new String(decryptedP2, StandardCharsets.UTF_8));

        String plaintext3 = "Exactly 16 Bytes";
        System.out.println("\nPlaintext: " + plaintext3);
        byte[] p3 = plaintext3.getBytes();

        byte[] encryptedP3 = aes.encrypt(key, p3);
        System.out.println("Encrypted Data:");
        System.out.println(formatHexPrint.formatHex(encryptedP3));

        byte[] decryptedP3 = aes.decrypt(key, encryptedP3);
        System.out.println("Decrypted Data:");
        System.out.println(formatHexPrint.formatHex(decryptedP3));
        System.out.println(new String(decryptedP3, StandardCharsets.UTF_8));
    }
}
