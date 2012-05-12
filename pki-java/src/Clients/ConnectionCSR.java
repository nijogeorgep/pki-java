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

	X509Certificate mycert; // the newly generated certificate will be stored here
	PrivateKey key;
	
	public ConnectionCSR(String ip, Integer port) {
		super(ip, port);
	}
	
	public void run() {
	    Security.addProvider(new BouncyCastleProvider());
	    try {
	    	
		    KeyPair   kp = KeyPairGenerator.getInstance("RSA").generateKeyPair(); // Générate the key pair
		    this.key = kp.getPrivate(); //Keep the private key
		    
		    String identite = ClientUtils.readIdentity(); //Read our identity
		    System.out.print("Please enter your password: ");
		    String pwd = ClientUtils.saisieString();
		    PKCS10CertificationRequest request = CSRManager.generate_csr(identite, kp); // Generate the CSR
		    
		    byte[] bytes = request.getEncoded(); //get the byte[] of the CSR
		    
		    out.write(bytes); //Write The CSR
		    
		    new String(this.read());
		    //Do nothing with it, it's just like a acknowledgement of the CSR
		    
		    out.write(MessageDigestUtils.digest(pwd)); // Digest the password to does not send it in clear
		    
		    byte[] rep = this.read();
		    X509Certificate cert  = CertificateUtils.certificateFromByteArray(rep); // Try to recreate the certificate from the byte[] read
		    if (cert == null) { // If it does not succeed it means that it has been refused and so the byte[] is the error message
		    	this.errormessage = new String(rep);
		    	this.finishedOK = false;
		    }
		    else {
		    	this.mycert = cert;
		    	this.finishedOK = true;
		    }
		    this.close();
	    }
	    catch(Exception e) {
	    	e.printStackTrace();
	    	this.errormessage = e.getMessage();
	    	this.finishedOK = false;
	    }
	}

	public boolean storeCertAndKey(KeyStore ks, String alcert, String alkey, String alpass) { //Store the certificate and the key using the aliases given in parameter
		try {
			ks.setCertificateEntry(alcert, this.mycert);
			Certificate[] chain = new Certificate[2];
			X509Certificate rootC = (X509Certificate) ks.getCertificate(Config.get("KS_ALIAS_CERT_CA","CA_Certificat"));
			X509Certificate intC = (X509Certificate) ks.getCertificate(Config.get("KS_ALIAS_CERT_CA_INTP","CA_Certificat"));
			chain[0] = rootC;
			chain[1] = intC;
			ks.setKeyEntry(alkey, this.key,alpass.toCharArray(), CertificateUtils.createNewChain(chain, this.mycert));
			ks.store(new FileOutputStream( Config.get("KS_PATH_USER","test.keystore.ks") ), Config.get("KS_PASS_USER","passwd").toCharArray());
			return true;
		}
		catch(Exception e) {
			return false;
		}
	}
}
