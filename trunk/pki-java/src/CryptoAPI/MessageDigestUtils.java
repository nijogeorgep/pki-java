package CryptoAPI;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.util.encoders.Base64;

public class MessageDigestUtils {

	public static byte[] digest(String s) {
		/*
		 * Digest the given String in SHA-1
		 */
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-1");
			md.update(s.getBytes());
	        return md.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static byte[] digest(byte[] data) {
		/*
		 * Digest the given byte[] in SHA-1
		 */
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-1");
			md.update(data);
	        return md.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static boolean checkDigest(byte[] d1, byte[] d2) {
		/*
		 * Return true if the digest are the sames, false otherwise
		 */
			return MessageDigest.isEqual(d1, d2);
	}
	
	public static String encodeB64Digest(byte[] digest) {
		/*
		 * Encode the given digest in Base64
		 */
		return new String(Base64.encode(digest));
	}
	
	public static byte[] decodeB64Digest(String encoded) {
		/*
		 * Decode the given String in Base64
		 */
		return Base64.decode(encoded);
	}
}
