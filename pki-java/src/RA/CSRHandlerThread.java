package RA;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.UnknownHostException;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import CryptoAPI.MessageDigestUtils;
import Ldap.ldaputils;

public class CSRHandlerThread extends Thread implements Runnable, CommunicationHandler {
	byte[] bytesread = null;
	byte[] bytestowrite = null;
	Integer distinguishValue = 1;
	PKCS10CertificationRequest request;
	/* ######## README #########
	 * (Lire d'abord RevocationRequest)
	 * Le fonctionnement est similaire a RevocationRequest sauf qu'il ne fait pas la même chose:
	 * Il lance aussi un thread autonome qui fait:
	 * 			- Vérifie l'identité de la personne qui fait la demande (normalement sa se fait avec des NSS etc) mais la on va juste supposer que la personne existe dans le LDAP.
	 * 			- Si la personne n'existe pas le demande de certificat est refusé et le thread s'arrete là (passe son status à refusé)
	 * 			- Si la personne existe on considère la demande de certificat comme valide et on se connecte au RA pour la faire signer.
	 * 			- On crée le certificat a partir de la CSR signé que le CA nous a renvoyé
	 * 			- On se connecte au repository pour envoyer le certificat
	 * 			- On passe le status a OK
	 *########################*/
    //the thread is created into the same class as EchoServer as a private class because I had considered it as a built-in subroutine of the server
	
	public CSRHandlerThread(PKCS10CertificationRequest req) {
		this.request = req;
	}
    	
    public void run()  { //method that implement Runnable
    	
    	this.setBytesToWrite("OK first".getBytes());
    	
    	for (;;) {
			if(hasSomethingToRead()) {
				byte[] bytes = this.getRead(); //Ici pour un CSR ce qu'on récupère c'est le password
				
				String uid = ldaputils.getUIDFromSubject(request.getSubject().toString());// on récupère l'uid a partir de la csr
				if(uid == null) {
					this.setBytesToWrite("Fail user not found".getBytes());
					break;
				}
				
				byte[] ldappass = ldaputils.getUserPassword(uid);
				
				if(MessageDigestUtils.checkDigest(bytes, ldappass)) {
					//this.setBytesToWrite("OK".getBytes());
					
					//---------- Connection au CA -------------
					Socket s;
					try {
						s = new Socket("localhost", 5555);
						DataOutputStream out = new DataOutputStream(s.getOutputStream()); //A noter que j'utilise des DataOutputStream et pas des ObjectOutputStream
						DataInputStream in = new DataInputStream(s.getInputStream());
						
						byte[] bytesrec = this.request.getEncoded(); //récupère le tableau de bytes de la requete
						
						out.write(bytesrec); //on envoie la requete
						
						byte[] reply  = read(in);
						
						System.out.println(reply);
						
						this.setBytesToWrite(reply);
						s.close();
						
					} catch (UnknownHostException e) {
						this.setBytesToWrite("Unknown host CA".getBytes());
						e.printStackTrace();
					} catch (IOException e) {
						this.setBytesToWrite("'IOError CA connection".getBytes());
						e.printStackTrace();
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
	public Integer getDistinguishNumber() {
		return this.distinguishValue;
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
