package CryptoAPI;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;

import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class AsymetricKeyManager {
	
	public static byte[] cipher(X509Certificate cert, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	/*
	 * Cipher the data with the certificate given in argument
	 */
		try {
			Cipher cipher = Cipher.getInstance("RSA");
		    cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
		    return cipher.doFinal(data);
		}
		catch(Exception e) {
			return null;
		}
	}
	
	
	public static byte[] decipher(PrivateKey key, byte[] data) {
	/*
	 * Decipher the data with the PrivateKey given in argument
	 */
		try {
			Cipher cipher = Cipher.getInstance("RSA");
		    cipher.init(Cipher.DECRYPT_MODE, key);
		    return cipher.doFinal(data);
		}
		catch(Exception e) {
			return null;
		}
	}
	
	public static byte[] sign(PrivateKey key, byte[] data) {
	/*
	 * Sign the data with the PrivateKey given in argument
	 */
		try {
			Signature sig = Signature.getInstance("SHA1withRSA");
		    sig.initSign(key);
		    
		    sig.update(data);
		    return sig.sign();
		}
		catch(Exception e) {
			return null;
		}
	}
	
	public static boolean verifySig(X509Certificate cert, byte[] dataoriginal, byte[] datasigned) {
	/*
	 * Verify the signature of datasigned with the dataoriginal using the given certificate
	 * @return: boolean if either the signature is good or not
	 */
		try {
			 Signature sig = Signature.getInstance("SHA1withRSA");
		     sig.initVerify(cert.getPublicKey()); //ou initVerify avec pubkey
		     sig.update(dataoriginal);
		     return sig.verify(datasigned);
		}
		catch (Exception e) {
			return false;
		}
	}
}
