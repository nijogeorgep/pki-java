package CryptoAPI;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;

public class AsymetricKeyManager {
	
	public static byte[] cipher(X509Certificate cert, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
		    cipher.init(Cipher.ENCRYPT_MODE, cert);
		    return cipher.doFinal(data);
		}
		catch(Exception e) {
			return null;
		}
	}
	
	public static byte[] decipher(PrivateKey key, byte[] data) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
		    cipher.init(Cipher.DECRYPT_MODE, key);
		    return cipher.doFinal(data);
		}
		catch(Exception e) {
			return null;
		}
	}
	
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException {
	    KeyPair   kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
	    X509Certificate cert =  CertificateManager.createSelfSignedCertificate("Coucou toto", kp);
	    System.out.println(cert.getPublicKey().getAlgorithm());
	}
}
