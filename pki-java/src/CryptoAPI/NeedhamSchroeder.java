package CryptoAPI;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class NeedhamSchroeder {

	BigInteger na;
	
	public static byte[] step1nonceAToB(X509Certificate certA, PrivateKey keyA , X509Certificate certB, BigInteger nonce) {
		// M3: A --> B:  {Na,A}Kb            en fait: { {Na}Ka', A }Kb
		try {
			//byte[] aEncodeNonce = nonce.toByteArray();
			CMSSignedData nonceSigned = CMSDataManager.signMessage(certA, keyA, nonce.toByteArray());
			byte[] nonceEncrypted = CMSDataManager.encryptMessage(nonceSigned.getEncoded(), certB);
			//return AsymetricKeyManager.cipher(b, aEncodeNonce);
			return nonceEncrypted;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] step2nonceAnonceBToA(X509Certificate certA, PrivateKey keyB, BigInteger nonceB, byte[] nonceEncrypted, boolean requireValidSig) {
		// M6: B --> A:   {Na,Nb}Ka
		try {
			//byte[] dec = AsymetricKeyManager.decipher(bPriv, nonceEncoded);
			CMSSignedData nonceSigned = new CMSSignedData((byte[])CMSDataManager.decryptMessage(nonceEncrypted, keyB));
			byte[] rawnonceA = (byte[]) CMSDataManager.verifySignedMessage(nonceSigned);
			if(rawnonceA == null && requireValidSig) {
				return null;
			}
			byte[] rawnonceB = nonceB.toByteArray();
			byte[] container = new byte[rawnonceA.length+rawnonceB.length];
			
			System.arraycopy(rawnonceA, 0, container, 0, rawnonceA.length);
			System.arraycopy(rawnonceB, 0, container, rawnonceA.length, rawnonceB.length);

			byte[] nonceAnonceBEncrypted = CMSDataManager.encryptMessage(container, certA);
			return nonceAnonceBEncrypted;
		} catch (CMSException e) {
			//e.printStackTrace();
		}
		return null;
	}

	public static BigInteger getnonceAFromStep1(PrivateKey keyB, byte[] nonceEncrypted) {
		try {
			CMSSignedData nonceSigned = new CMSSignedData((byte[])CMSDataManager.decryptMessage(nonceEncrypted, keyB));
			byte[] rawnonceA = (byte[]) CMSDataManager.verifySignedMessage(nonceSigned);
			return new BigInteger(rawnonceA);
		}
		catch(Exception e) {
			return null;
		}
	}
	public static byte[] step3nonceBToB(PrivateKey keyA, X509Certificate certB, byte[] dataEncrypted, BigInteger nonceAOrig) {
		try {
			byte[] container = (byte[]) CMSDataManager.decryptMessage(dataEncrypted, keyA);
			byte[] nonceA = Arrays.copyOf(container, nonceAOrig.toByteArray().length);
			byte[] nonceB = Arrays.copyOfRange(container, nonceAOrig.toByteArray().length, container.length);
			if(nonceAOrig.equals(new BigInteger(nonceA))){
				System.out.println("OK");
				byte[] nonceBEncrypted = CMSDataManager.encryptMessage(nonceB, certB);
				return nonceBEncrypted;
			}
			else
				return null; //return null if the nonce is not equal
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static BigInteger getNonceBFromStep2(PrivateKey keyA, byte[] dataEncrypted, BigInteger nonceAOrig) {
		try {
			byte[] container = (byte[]) CMSDataManager.decryptMessage(dataEncrypted, keyA);
			byte[] nonceB = Arrays.copyOfRange(container, nonceAOrig.toByteArray().length, container.length);
			return new BigInteger(nonceB);
		}
		catch(Exception e) {
			return null;
		}
	}
			
	public static boolean step3received(PrivateKey keyB, BigInteger nonceBOrig, byte[] nonceBEnc) {
		byte[] nonceB = (byte[]) CMSDataManager.decryptMessage(nonceBEnc, keyB);
		if(nonceBOrig.equals(new BigInteger(nonceB))){
			System.out.println("OK");
			return true;
		}
		else
			return false; //return null if the nonce is not equal
	}
	
	public static BigInteger generateNonce() {
		Random randomGenerator = new Random();
		return new BigInteger(53, randomGenerator);
	}
	
	public static byte[] generateSessionKey(BigInteger nonceA, BigInteger nonceB) {
		byte[] rawA = nonceA.toByteArray();
		byte[] rawB = nonceB.toByteArray();
		byte[] seed = new byte[rawA.length+rawB.length];
		
		System.arraycopy(rawA, 0, seed, 0, rawA.length);
		System.arraycopy(rawB, 0, seed, rawA.length, rawB.length);
		return MessageDigestUtils.digest(seed);
	}
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
	
		ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray()); //ouvre le keystore
	
		X509Certificate	 certA = (X509Certificate) ks.getCertificate("personne1_certificat"); //certificat du client dont on veut vérifier l'identitée
		X509Certificate certB = (X509Certificate) ks.getCertificate("CA_SigningOnly_Certificate"); //certificat qui signe les crl/ocsp on l'utilise dans analyseOCSPResponse pour vérifier la signature de la reponse
		PrivateKey keyA = (PrivateKey) ks.getKey("personne1_private", "monpassP1".toCharArray());
		PrivateKey keyB = (PrivateKey) ks.getKey("CA_SigningOnly_Private", "passwordSigningCert".toCharArray());
		
		BigInteger nonceA = new BigInteger("123");
		BigInteger nonceB = new BigInteger("546");
		
		byte[] step1 = step1nonceAToB(certA, keyA, certB, nonceA);
		byte[] step2 = step2nonceAnonceBToA(certA, keyB, nonceB, step1, true);
		byte[] step3a = step3nonceBToB(keyA, certB, step2, nonceA);
		System.out.println(step3a);
		System.out.println(step3received(keyB, nonceB, step3a));
	}
}
