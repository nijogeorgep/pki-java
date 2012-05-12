package RA;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.UnknownHostException;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;


import CryptoAPI.CertificateUtils;
import CryptoAPI.MessageDigestUtils;
import Ldap.ldaputils;
import Utils.Config;

public class CSRHandlerThread extends Thread implements Runnable, CommunicationHandler {
	/*
	 * Class the extends Thread and implement Runnable,CommunicationHandler. It will independently connect to the CA, send the CSR
	 * receive the certificate, and forward it to the RaServer class to will send it to the user
	 */
	byte[] bytesread = null;
	byte[] bytestowrite = null;
	PKCS10CertificationRequest request;
	String pass;
	
	public CSRHandlerThread(PKCS10CertificationRequest req, String pass) {
		this.request = req;
		this.pass = pass;
	}
    	
    public void run()  {
    	
    	this.setBytesToWrite("OK first".getBytes()); // If we are here it means that we have received a well formed CSR so we acknowledge it and wait for the password
    	
    	for (;;) {
			if(hasSomethingToRead()) { //Wait for the password
				byte[] bytes = this.getRead(); //Read the password
				
				String uid = ldaputils.getUIDFromSubject(request.getSubject().toString());//Contact LDAP to get the uid of the user using the subject of the CSR
				if(uid == null) {
					this.setBytesToWrite("Fail user not found".getBytes());
					break;
				}
				
				byte[] ldappass = ldaputils.getUserPassword(uid,pass); //Get the password of the given user
				
				if(MessageDigestUtils.checkDigest(bytes, ldappass)) { // Check if the password sent is the same than the one on the LDAP
					System.out.println("User pass OK");
				
					//---------- CA connection -------------
					Socket s;
					try {
						int port = new Integer(Config.get("PORT_CA","6666"));
						s = new Socket( Config.get("IP_CA","localhost"), new Integer( port )); // Connect to the CA

						DataOutputStream out = new DataOutputStream(s.getOutputStream());
						DataInputStream in = new DataInputStream(s.getInputStream());
						
						byte[] bytesrec = this.request.getEncoded(); //Get the CSR as byte[]
						
						out.write(bytesrec); //send it to the CA
						
						byte[] reply  = read(in);
						
						System.out.println(reply);
						
						this.setBytesToWrite(reply); // Forward the reply without checking anything
						s.close();
						ldaputils.setCertificateUser(CertificateUtils.certificateFromByteArray(reply), uid, Config.get("USERS_BASE_DN",""),pass);
						
					} catch (UnknownHostException e) {
						this.setBytesToWrite("Unknown host CA".getBytes());
					} catch (IOException e) {
						this.setBytesToWrite("IOError CA connection".getBytes());
					}
					//----------------------------------------------
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
