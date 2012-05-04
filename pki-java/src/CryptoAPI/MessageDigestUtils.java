package CryptoAPI;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;

import Ldap.ldaputils;
import Utils.Config;

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
	
	public static byte[] digest(byte[] data) {
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
	
	public static String encodeB64Digest(byte[] digest) {
		return new String(Base64.encode(digest));
	}
	
	public static byte[] decodeB64Digest(String encoded) {
		return Base64.decode(encoded);
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, OperatorCreationException, IOException {
		/*
		String uid = "1234";
		//ldaputils.setUserPassword(MessageDigestUtils.digest("caca"), "uid="+uid+","+Config.get("USERS_BASE_DN", ""));
		
		byte[] ldappass = ldaputils.getUserPassword(uid);
		System.out.println(new String(ldappass));
		
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		md.update("cac".getBytes());
		byte[] d1 = md.digest();
		System.out.println(new String(d1));
		
		System.out.println(MessageDigestUtils.checkDigest(ldappass, d1));
		*/
	}
}
