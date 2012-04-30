package Ldap;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;

import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.x509.extension.X509ExtensionUtil;


import CryptoAPI.CRLManager;
import CryptoAPI.CertificateUtils;
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
	
	public static boolean deleteUser(String dn)
	{
    try
    {
      LDAP ldap = new LDAP();
      //ldap.init("ldap://87.98.166.65:389"); //Could be ldap://localhost:398/ou=People ...
      String url;
      url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
      ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), Config.get("LDAP_PASS","PKICrypto"));
      ldap.deleteObject(dn);
      ldap.close();
    }
    catch (NamingException e)
    {
      e.printStackTrace();
    }
   
    
	  return false ;
	}
	
	public static void setCertificateCA(X509Certificate cert, String dn) {
		LDAP ldap = new LDAP();
		try {
			String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
			//System.out.println(url);
			ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), Config.get("LDAP_PASS","PKICrypto"));
			
			ldap.modifAttribute(DirContext.REPLACE_ATTRIBUTE, dn, "cACertificate;binary", cert.getEncoded());
			
			ldap.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void setCRL(X509CRLHolder crl, String dn) {
		LDAP ldap = new LDAP();
		try {
			String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
			//System.out.println(url);
			ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), Config.get("LDAP_PASS","PKICrypto"));
			
			ldap.modifAttribute(DirContext.REPLACE_ATTRIBUTE, dn, "certificateRevocationList;binary", crl.getEncoded());
			
			ldap.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	//setCertificate
	public static void setCertificateUser(X509Certificate cert,String uid, String dn) {
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
			return CertificateUtils.certificateFromByteArray(res);
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
	
	public static void setUserPassword(byte[] pass, String dn) {
		LDAP ldap = new LDAP();
		try {
			String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
			//System.out.println(url);
			ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), Config.get("LDAP_PASS","PKICrypto"));
			
			ldap.modifAttribute(DirContext.REPLACE_ATTRIBUTE, dn, "userPassword", pass);
			
			ldap.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public static X509CRLHolder getCRL(String dn, String ou) {
		LDAP ldap = new LDAP();
		//ldap.init("ldap://87.98.166.65:389"); //Could be ldap://localhost:398/ou=People ...
		try {
		String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
		ldap.init(url);
		
		byte[] res = (byte[]) ldap.getAttribute(dn, "ou="+ou, "certificateRevocationList;binary");
		
		ldap.close();
		return new X509CRLHolder(res);
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	  public static String getUIDFromSubject(String ident)
	  {
	    LDAP ldap = new LDAP();
	    //ldap.init("ldap://87.98.166.65:389"); //Could be ldap://localhost:398/ou=People ...
	    try 
	    {
	      String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
	      ldap.init(url);
	      String[] id = ident.split(" ");
	      String[] cnTmp = id[0].split("=");
	      String cn = cnTmp[1];
	      String sn = id[1];
	      String uid = ldap.searchAttribute(Config.get("USERS_BASE_DN", ""), cn,"sn="+sn, "uid");
	      ldap.close();
	      return uid;
	    }
	    catch(Exception e) 
	    {
	      e.printStackTrace();
	      return null;
	    }
	  }
	  
	  public static X509CRLHolder getCRLFromURL(String url) {
		  LDAP ldap = new LDAP();
		  try {
			  ldap.init(url);
			  DirContext o = (DirContext) ldap.getContext().lookup("");
		      Attributes attributes = o.getAttributes("");
		      ldap.close();
		      return new X509CRLHolder((byte[]) attributes.get("certificateRevocationList;binary").get());
		  }
		  catch(Exception e) {
			  return null;
		  }
	  }
	  
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException, KeyStoreException {
		//createNewUser("2222", "Pierre", "Junk", "coucou".getBytes());
		//System.out.println(getUserPassword("1234"));
		X509Certificate cert = ldaputils.getCertificate("1234");
		System.out.println(cert);
		//System.out.println(cert);
		/*
		String url = CertificateUtils.crlURLFromCert(cert);
		System.out.println(url);
		X509CRL crl = CRLManager.CRLFromCrlHolder(ldaputils.getCRLFromURL(url, "1234"));
		
		System.out.println(crl);
		*//*
		KeyPair		keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		X509Certificate caCert = Playground.setup_ca.createSelfSignedCertificate("CA Root", "CA Root", keyPair);
		setCertificate(caCert, "1234");
		*/
		
		/*
		X509Certificate cert = getCertificate("1234");
		System.out.println(cert);
		*/
	//	X509CRLHolder crl = getCRL("dc=pkirepository,dc=org","rootCA");
	//	System.out.println(crl.getEncoded());
	}


	
}
