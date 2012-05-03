package Clients;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import Utils.Config;

import CryptoAPI.CSRManager;
import CryptoAPI.CertificateUtils;
import CryptoAPI.MessageDigestUtils;

public class ConnectionCSR extends Connection {

	X509Certificate mycert;
	PrivateKey key;
	
	public ConnectionCSR(String ip, Integer port) {
		super(ip, port);
	}
	
	public void run() {
	    Security.addProvider(new BouncyCastleProvider());
	    try {
	    	
		    KeyPair   kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		    this.key = kp.getPrivate();
		    
		    String identite = ClientUtils.readIdentity();
		    System.out.println("Entrez votre mot de passe");
		    String pwd = ClientUtils.saisieString();
		    PKCS10CertificationRequest request = CSRManager.generate_csr(identite, kp);
		    
		    byte[] bytes = request.getEncoded(); //récupère le tableau de bytes de la requete
		    
		    out.write(bytes); //on envoie la requete
		    
		    String reply  = new String(this.read());
		    //Do nothing with it, it's just like a ACK
		    //System.out.println(new String(reply));
		    
		    out.write(MessageDigestUtils.digest(pwd));
		    
		    byte[] rep = this.read();
		    X509Certificate cert  = CertificateUtils.certificateFromByteArray(rep);
		    if (cert == null) {
		      //System.out.println(new String(rep));
		    	this.errormessage = new String(rep);
		    	this.finishedOK = false;
		    }
		    else {
		    	//System.out.println(cert.toString());
		    	this.mycert = cert;
		    	this.finishedOK = true;
		    }
		    this.close();
	    }
	    catch(Exception e) {
	    	e.printStackTrace();
	    	this.errormessage = e.getMessage();
	    }
	}

	public boolean storeCertAndKey(KeyStore ks, String alcert, String alkey, String alpass) {
		try {
			ks.setCertificateEntry(alcert, this.mycert);
			Certificate[] chain = ks.getCertificateChain("CA_IntermediairePeople_Private");
	
			ks.setKeyEntry(alkey, this.key,alpass.toCharArray(), CertificateUtils.createNewChain(chain, this.mycert));
			ks.store(new FileOutputStream( Config.get("USER_KEYSTORE_PATH","test.keystore.ks") ), Config.get("USER_KEYSTORE_PASS","passwd").toCharArray());
			return true;
		}
		catch(Exception e) {
			return false;
		}
	}
}
