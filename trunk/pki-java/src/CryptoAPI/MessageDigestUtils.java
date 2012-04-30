package CryptoAPI;

import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;

public class MessageDigestUtils {

	public static byte[] digest(String s) {
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
	
	public static boolean checkDigest(byte[] d1, byte[] d2) {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-1");
			//md.update(s.getBytes());
			return md.isEqual(d1, d2);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
	}
	
	public static void main(String[] args) {
		byte[] d1 = MessageDigestUtils.digest("coucou");
		System.out.println(MessageDigestUtils.checkDigest("coucou".getBytes(), "coucou".getBytes()));
	}
}
