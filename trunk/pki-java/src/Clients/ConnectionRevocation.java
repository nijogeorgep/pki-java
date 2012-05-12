package Clients;

import java.io.IOException;
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
			
			String uid = ldaputils.getUIDFromSubject("CN="+identite); // Get our uid from the Identity read at the keyboard
			
			System.out.print("Please enter your password: ");
			String pwd = ClientUtils.saisieString();
			
			
			
			try {
				  out.write(uid.getBytes()); //Send the uid
				  
				  new String(this.read()); // Read the acknowledgement even if we don't care if it
				  
				  out.write(MessageDigestUtils.digest(pwd)); // Write the digest of our password to prove our identity
				  
				  String res  = new String(this.read()); // Read the reply
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
