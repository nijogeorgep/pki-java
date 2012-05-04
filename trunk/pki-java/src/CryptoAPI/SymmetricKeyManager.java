package CryptoAPI;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Base64;


public class SymmetricKeyManager {

	public static byte[] cipher(byte[] key, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

			//MessageDigest sha = MessageDigest.getInstance("SHA-1");
			//key = sha.digest(key);
			key = Arrays.copyOf(key, 16); // use only first 128 bit
 
	       SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
	       // Instantiate the cipher
	       Cipher cipher = Cipher.getInstance("AES");

	       cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		
	       return cipher.doFinal(data);
	}
	
	public static byte[] decipher(byte[] key, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
			
			//MessageDigest sha = MessageDigest.getInstance("SHA-1");
			//key = sha.digest(key);
			key = Arrays.copyOf(key, 16); // use only first 128 bit

	       SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
	       // Instantiate the cipher
	       Cipher cipher = Cipher.getInstance("AES");

	       cipher.init(Cipher.DECRYPT_MODE, skeySpec);
		
	       return cipher.doFinal(data);
	}

	public static void main(String[] agrs) {
		byte[] pass = "password".getBytes();
		byte[] s = "coucou".getBytes();
		try {
			byte[] res = cipher(pass, s);
			System.out.println(new String(res));
			System.out.println(new String(decipher(pass, res)));
			
			 System.out.println(new String(Base64.encode(res)));
		}
		catch(Exception e) { e.printStackTrace(); }
		
	}
}
