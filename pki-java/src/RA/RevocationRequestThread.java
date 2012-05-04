package RA;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import CryptoAPI.CRLManager;
import CryptoAPI.CertificateUtils;
import CryptoAPI.MessageDigestUtils;
import Ldap.ldaputils;
import Utils.Config;


public class RevocationRequestThread extends Thread implements Runnable, CommunicationHandler {
	byte[] bytesread = null;
	byte[] bytestowrite = null;
	X509Certificate caSignerCert;
	PrivateKey caSignerKey;
	String uid = "";
	String pass;
/* ######## README #########
 * Bon j'explique brievement l'idée qui m'est passé par la tête.
 * Cet objet sera crée pour chaque demande de revocation faite auprès du RA.
 * Concrètement ce quie fait cet objet:
 * Il lancera un thread autonome (pour pas bloquer le RA) qui se connectera au CA pour faire signer la demande de revocation.
 * Puis il se connectera au Repository pour envoyer la revocation.
 * Une methode permettra au RA de savoir a tout moment ou en est la progression de la revocation, et si elle à échoué ou pas.
 * 
 * Comment ça va marcher coté RA ?
 * Concretement lorsque le RA reçoit d'un client une demande de révocation il crée un objet RevocationRequest qu'il lance et met en attachment de la SelectionKey
 * A chaque fois qu'il va looper sur les Keys et tomber sur la SelectionKeys qui contient cet objet il va consulter son status. Tant que c'est en progression il le laisse faire.
 * Ensuite que le résultat soit positif ou négatif il renvoie la réponse récupérée, puis ferme la socket.
 *########################*/
	
	public RevocationRequestThread(String id,String pass) {
		this.uid = id;
		KeyStore ks;
		try {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());
			this.caSignerCert = (X509Certificate) ks.getCertificate("CA_SigningOnly_Certificate");
			this.caSignerKey = (PrivateKey) ks.getKey("CA_SigningOnly_Private", Config.get("PASSWORD_CA_SIG","").toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
    	
    public void run()  { //method that implement Runnable
    	
    	this.setBytesToWrite("OK first".getBytes());
    	
    	for (;;) {
			if(hasSomethingToRead()) {
				byte[] bytes = this.getRead(); //Ici pour un CSR ce qu'on récupère c'est le password
				
				byte[] ldappass = ldaputils.getUserPassword(this.uid,pass);
				
				if(MessageDigestUtils.checkDigest(bytes, ldappass)) {
					//try {
						//System.out.println(uid);
						X509Certificate cert = ldaputils.getCertificate(this.uid);
						//System.out.println(cert);
						X509CRLHolder holder = ldaputils.getCRLFromURL(CertificateUtils.crlURLFromCert(cert));
						System.out.println(holder);
						BigInteger ser = cert.getSerialNumber();
						X509CRLHolder newcrl = CRLManager.updateCRL(holder, this.caSignerCert, this.caSignerKey, ser, CRLReason.privilegeWithdrawn);
						ldaputils.setCRL(newcrl, Config.get("USERS_BASE_DN", ""),pass);
						this.setBytesToWrite("Done".getBytes());
					//}
					//catch(Exception e) {
					//	e.printStackTrace();
					//	this.setBytesToWrite("not done".getBytes());
					//}
				}
				else {
					this.setBytesToWrite("Fail password wrong".getBytes());
				}

				break;
			}
    		try {
				Thread.sleep(100);// avoid to load CPU at 100%
			} catch (InterruptedException e) {	break; }
			
    	}
    }
    
    private byte[] getRead() {
    	return this.bytesread;
    }
    
    private boolean hasSomethingToRead() {
    	return this.bytesread != null;
    }
    
    private void setBytesToWrite(byte[] bts) {
    	this.bytestowrite = bts;
    }
    
	@Override
	public void setRead(byte[] bts) {
		this.bytesread = bts;
	}

	@Override
	public byte[] getBytesToWrite() {
		return this.bytestowrite;
	}

	@Override
	public void resetBytesToWrite() {
		this.bytestowrite = null;
	}
	
	public static byte[] read(InputStream in) throws IOException {
		byte[] res = new byte[4096]; //Créer un tableau très grand. (Je m'attends a tout recevoir d'un coup j'ai pas envie de me faire chier)
		int read = in.read(res); //Je lis
		if (read == -1) { //si on a rien lu c'est que le serveur a eu un problème
				throw new IOException();
		}
		
		byte[] res_fitted = new byte[read]; //je déclare un tableau de la taille juste
		for (int i=0; i < read; i++) { //je recopie le byte dedans
			res_fitted[i] = res[i];
		}
		return res_fitted;
	}
	
}
