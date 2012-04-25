package Ldap;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.operator.OperatorCreationException;


import Utils.Config;

public class ldaputils {

	
	public static boolean createNewUser(String uid, String commonname, String surname, byte[] pass) throws IOException {
		try {
			LDAP ldap = new LDAP();
			//ldap.init("ldap://87.98.166.65:389"); //Could be ldap://localhost:398/ou=People ...
			String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
			//System.out.println(url);
			ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), Config.get("LDAP_PASS","PKICrypto"));
			
			String distinguishedName = "uid=" + uid +";"+ Config.get("USERS_BASE_DN", "");
			Attributes newAttributes = new BasicAttributes(true);
			Attribute oc = new BasicAttribute("objectclass");
			oc.add("top");
			oc.add("person");
			oc.add("uidObject");
			oc.add("pkiUser");
			newAttributes.put(oc);
			newAttributes.put(new BasicAttribute("uid", uid));
			newAttributes.put(new BasicAttribute("cn", commonname));
			newAttributes.put(new BasicAttribute("sn", surname));
			newAttributes.put(new BasicAttribute("userPassword", pass));
			  
			System.out.println("Name: " + commonname + " Attributes: " + newAttributes.toString());
			ldap.ctx.createSubcontext(distinguishedName, newAttributes);
			
			ldap.close();
			return true;
		}
		catch(NamingException e) {
			return false;
		}
	}
	
	//setCertificate
	public static void setCertificate(X509Certificate cert,String uid) {
		LDAP ldap = new LDAP();
		try {
			String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
			//System.out.println(url);
			ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), Config.get("LDAP_PASS","PKICrypto"));
			
			ldap.modifAttribute(DirContext.REPLACE_ATTRIBUTE,  "uid=" + uid +";"+ Config.get("USERS_BASE_DN", ""), "userCertificate;binary", cert.getEncoded());
			
			ldap.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	
	public static X509Certificate getCertificate(String uid) {
		LDAP ldap = new LDAP();
		//ldap.init("ldap://87.98.166.65:389"); //Could be ldap://localhost:398/ou=People ...
		try {
			String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
			ldap.init(url);
			
			byte[] res = (byte[]) ldap.getAttribute(Config.get("USERS_BASE_DN", ""), "uid="+uid, "userCertificate;binary");
			
			
			ldap.close();
			return Playground.CertificateUtils.certificateFromByteArray(res);
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] getUserPassword(String uid) {
		LDAP ldap = new LDAP();
		//ldap.init("ldap://87.98.166.65:389"); //Could be ldap://localhost:398/ou=People ...
		try {
		String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
		ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), Config.get("LDAP_PASS","PKICrypto"));
		
		byte[] res = (byte[]) ldap.getAttribute(Config.get("USERS_BASE_DN", ""), "uid="+uid, "userPassword");

		ldap.close();
		return res;
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	
	public static X509CRLHolder getCRL(String url,String organizationalUnit) {
		LDAP ldap = new LDAP();
		//ldap.init("ldap://87.98.166.65:389"); //Could be ldap://localhost:398/ou=People ...
		try {
		//String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
		ldap.init(url);
		
		byte[] res = (byte[]) ldap.getAttribute(Config.get("USERS_BASE_DN", ""), "ou="+organizationalUnit, "certificateRevocationList");
		
		ldap.close();
		return new X509CRLHolder(res);
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
		//createNewUser("2222", "Pierre", "Junk", "coucou".getBytes());
		//System.out.println(getUserPassword("1234"));
		
		/*
		KeyPair		keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		X509Certificate caCert = Playground.setup_ca.createSelfSignedCertificate("CA Root", "CA Root", keyPair);
		setCertificate(caCert, "1234");
		*/
		
		/*
		X509Certificate cert = getCertificate("1234");
		System.out.println(cert);
		*/
	}
	
}
