package Clients;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import CryptoAPI.MessageDigestUtils;
import Ldap.ldaputils;

public class ConnectionRevocation extends Connection {

	  public ConnectionRevocation(String ip, Integer port) {
		  super(ip, port);
	  }
	
	  public void run() {
			Security.addProvider(new BouncyCastleProvider());
			
			String identite = ClientUtils.readIdentity();
			
			String uid = ldaputils.getUIDFromSubject("CN="+identite);
			
			System.out.print("Please enter your password: ");
			String pwd = ClientUtils.saisieString();
			
			
			
			try {
				  out.write(uid.getBytes()); //on envoie la requete
				  
				  String reply  = new String(this.read());
				  
				  out.write(MessageDigestUtils.digest(pwd));
				  
				  String res  = new String(this.read());
				  if (res.equals("Done"))
					  this.finishedOK = true;
				  else {
					  this.errormessage = res;
					  this.finishedOK = false;
				  }
			}
			catch (IOException e) {
				  e.printStackTrace();
				  this.errormessage = e.getMessage();
				  this.finishedOK = false;
			} 
	  }
	  
	  
}
