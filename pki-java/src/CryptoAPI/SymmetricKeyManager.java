package CryptoAPI;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;



public class SymmetricKeyManager {

	public static byte[] cipher(byte[] key, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
			/*
			 * Cipher in AES the given data with the key.
			 * Note: Does not matter the size of the key only the 128 first bits will be taken as key
			 */
			key = Arrays.copyOf(key, 16); // use only first 128 bit
 
	       SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
	      
	       Cipher cipher = Cipher.getInstance("AES"); // Instantiate the cipher

	       cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		
	       return cipher.doFinal(data);
	}
	
	public static byte[] decipher(byte[] key, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
			/*
			 * Decipher in AES the given data using the key
			 * Note: Does not matter the size of the key only the 128 first bits will be used
			 */
			key = Arrays.copyOf(key, 16); // use only first 128 bit

	       SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
	       
	       Cipher cipher = Cipher.getInstance("AES"); // Instantiate the cipher

	       cipher.init(Cipher.DECRYPT_MODE, skeySpec);
		
	       return cipher.doFinal(data);
	}

}
