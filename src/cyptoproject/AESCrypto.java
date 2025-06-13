import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class AESCrypto{
    private static final int IV_SIZE = 16;
    private static final int KEY_SIZE = 128;
    private static SecretKeySpec getKeyFromPassword(String password,byte[]salt)throws Exception{
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(),salt,65536,KEY_SIZE);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes,"AES");
    }
    public static String encrypt(String input,String password)throws Exception{
        byte[] salt = new byte[8];
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        random.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec key = getKeyFromPassword(password, salt);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);
        byte[]encrypted = cipher.doFinal(input.getBytes());
        byte[]output = new byte[salt.length+iv.length+encrypted.length];
        System.arraycopy(salt,0,output,0,salt.length);
        System.arraycopy(iv,0,output,salt.length,iv.length);
        System.arraycopy(encrypted,0,output,salt.length + iv.length,encrypted.length);
        
        return Base64.getEncoder().encodeToString(output);
    }
    public static String decrypt(String encryptedText,String password)throws Exception{
        byte[]input = Base64.getDecoder().decode(encryptedText);
        byte[] salt = new byte[8];
        byte[] iv = new byte[IV_SIZE];
        byte[] encrypted = new byte[input.length-salt.length-iv.length];
        
        System.arraycopy(input,0,salt,0,salt.length);
        System.arraycopy(input,salt.length,iv,0,iv.length);
        System.arraycopy(input,salt.length + iv.length,encrypted,0,encrypted.length);  
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec key = getKeyFromPassword(password, salt);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,key,ivSpec);
        byte[]original = cipher.doFinal(encrypted);
        
        return new String(original);
    }
    public static void main(String[]args){
        Scanner scan = new Scanner(System.in);
        try{
            System.out.println("Enter password:");
            String password = scan.nextLine();
            System.out.println("Enter text to be encrypted:");
            String plaintext = scan.nextLine();
            String encrypted = encrypt(plaintext,password);
            System.out.println("Encrypted(Base64):"+encrypted);
            System.out.println("Decrypting....");
            String decrypted = decrypt(encrypted,password);
            System.out.println("Decrypted:"+decrypted);
        }
        catch (Exception e){
            System.err.println("Encryption/Decryption error:"+e.getMessage());
        }
        scan.close();
    }
}
