import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class Main {
   


    public static final String secretKey = "secretsecretsecr";

    public static final String plaintext1 = "AES USES AMATRIX";

    public static void main(String[] args) {
        byte[] p1 = plaintext1.getBytes();
        byte[] key = secretKey.getBytes();
        HexFormat formatHexPrint = HexFormat.ofDelimiter(" ").withUpperCase();
        AES aes = new AES();

        byte[] encryptedP1 = aes.encrypt(key, p1);
        System.out.println("Encrypted Data:");
        System.out.println(formatHexPrint.formatHex(encryptedP1));

        byte[] decryptedP1 = aes.decrypt(key, encryptedP1);
        System.out.println("Decrypted Data:");
        System.out.println(formatHexPrint.formatHex(decryptedP1));
        System.out.println(new String(decryptedP1, StandardCharsets.UTF_8));
    }

    
}
