package RA;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

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
				
				if(new String(bytes).equals("coucou")) {
					this.setBytesToWrite("OK second".getBytes());
				}
				else
					this.setBytesToWrite("NOP".getBytes());
				break;
			}
    		try {
				Thread.sleep(5000);// avoid to load CPU at 100%
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
}
