package RA;


import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;

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

	public RevocationRequestThread(String id,String pass, X509Certificate sigCert, PrivateKey key) {
		this.uid = id;
		this.caSignerCert = sigCert;
		this.caSignerKey = key;
		this.pass = pass;
	}
    	
    public void run()  { //method that implement Runnable
    	
    	this.setBytesToWrite("OK first".getBytes()); // Has for CSRHandler if we are here it means we have already received the identity
    	
    	for (;;) {
			if(hasSomethingToRead()) {
				byte[] bytes = this.getRead(); //So what we read here is the password
				
				byte[] ldappass = ldaputils.getUserPassword(this.uid,pass); //Get the user password
				
				if(MessageDigestUtils.checkDigest(bytes, ldappass)) { // If equal to the one received continue

						X509Certificate cert = ldaputils.getCertificate(this.uid); //Get the user certificate
						X509CRLHolder holder = ldaputils.getCRLFromURL(CertificateUtils.crlURLFromCert(cert)); // Get the CRL of his issuer
						
						BigInteger ser = cert.getSerialNumber(); // Get the serial number of the certificate
						
						// Call the method of the CryptoAPI to update an existing CRL
						X509CRLHolder newcrl = CRLManager.updateCRL(holder, this.caSignerCert, this.caSignerKey, ser, CRLReason.privilegeWithdrawn);
						
						//Send it back on the LDAP
						ldaputils.setCRL(newcrl, Config.get("USERS_BASE_DN", ""),pass);
						
						//Delete the user certificate on the LDAP to prevent another user to download it whereas it is revoked.
						ldaputils.deleteUserCertificate("uid="+this.uid+","+Config.get("USERS_BASE_DN",""), pass);
						this.setBytesToWrite("Done".getBytes());
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
		byte[] res = new byte[4096];
		int read = in.read(res);
		if (read == -1) {
				throw new IOException();
		}
		
		byte[] res_fitted = new byte[read];
		for (int i=0; i < read; i++) {
			res_fitted[i] = res[i];
		}
		return res_fitted;
	}
	
}
