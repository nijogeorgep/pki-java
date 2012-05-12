package Ldap;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;

import org.bouncycastle.cert.X509CRLHolder;

import CryptoAPI.CertificateUtils;
import Utils.Config;

public class ldaputils {

	
	public static boolean createNewUser(String uid, String commonname, String surname, byte[] pass, String ldappass) throws IOException {
		/*
		 * Wrapper to add an user quickly
		 */
		try {
			LDAP ldap = new LDAP();
			String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
			ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), ldappass);
			
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
	
	public static boolean deleteUser(String dn, String ldappass) {
		try {
			LDAP ldap = new LDAP();
			String url;
			url = "ldap://" + Config.get("LDAP_IP", "localhost") + ":"
					+ Config.get("LDAP_PORT", "389");
			ldap.initAuth(url, Config.get("LDAP_ADMIN_DN",
					"cn=admin,dc=pkirepository,dc=org"), ldappass);
			ldap.deleteObject(dn);
			ldap.close();
		} catch (NamingException e) {
			e.printStackTrace();
		}
		return false ;
	}
	
	public static void setCertificateCA(X509Certificate cert, String dn, String ldappass) {
		LDAP ldap = new LDAP();
		try {
			String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");

			ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), ldappass);
			
			ldap.modifAttribute(DirContext.REPLACE_ATTRIBUTE, dn, "cACertificate;binary", cert.getEncoded());
			
			ldap.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void setCRL(X509CRLHolder crl, String dn, String ldappass) {
		LDAP ldap = new LDAP();
		try {
			String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");

			ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), ldappass);
			
			ldap.modifAttribute(DirContext.REPLACE_ATTRIBUTE, dn, "certificateRevocationList;binary", crl.getEncoded());
			
			ldap.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	

	public static void setCertificateUser(X509Certificate cert,String uid, String dn, String ldappass) {
		LDAP ldap = new LDAP();
		try {
			String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");

			ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), ldappass);
			
			ldap.modifAttribute(DirContext.REPLACE_ATTRIBUTE,  "uid=" + uid +";"+ Config.get("USERS_BASE_DN", ""), "userCertificate;binary", cert.getEncoded());
			
			ldap.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	
	public static X509Certificate getCertificate(String uid) {
		LDAP ldap = new LDAP();

		try {
			String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
			ldap.init(url);
			
			byte[] res = (byte[]) ldap.getAttribute(Config.get("USERS_BASE_DN", ""), "uid="+uid, "userCertificate;binary");
			
			
			ldap.close();
			return CertificateUtils.certificateFromByteArray(res);
		}
		catch(Exception e) {
			return null;
		}
	}

	
	public static X509Certificate getCaCertificate(String dn, String ou) {
		LDAP ldap = new LDAP();
		try {
			String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
			ldap.init(url);
			
			byte[] res = (byte[]) ldap.getAttribute(dn, "ou="+ou, "cACertificate;binary");
			
			ldap.close();
			return CertificateUtils.certificateFromByteArray(res);
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static byte[] getUserPassword(String uid, String ldappass) {
		LDAP ldap = new LDAP();

		try {
		String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");
		ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), ldappass);
		
		byte[] res = (byte[]) ldap.getAttribute(Config.get("USERS_BASE_DN", ""), "uid="+uid, "userPassword");

		ldap.close();
		return res;
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static void setUserPassword(byte[] pass, String dn, String ldappass) {
		LDAP ldap = new LDAP();
		try {
			String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");

			ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), ldappass);
			
			ldap.modifAttribute(DirContext.REPLACE_ATTRIBUTE, dn, "userPassword", pass);
			
			ldap.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void deleteUserCertificate(String dn, String ldappass) {
		LDAP ldap = new LDAP();
		try {
			String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");

			ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), ldappass);
			
			ldap.modifAttribute(DirContext.REMOVE_ATTRIBUTE, dn, "userCertificate;binary", null);
			
			ldap.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public static X509CRLHolder getCRL(String dn, String ou) {
		LDAP ldap = new LDAP();

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
	
	public static String getUIDFromSubject(String ident) {
		LDAP ldap = new LDAP();

		try {
			String url = "ldap://" + Config.get("LDAP_IP", "localhost") + ":"
					+ Config.get("LDAP_PORT", "389");
			ldap.init(url);
			String[] id = ident.split(" ");
			String[] cnTmp = id[0].split("=");
			String cn;
			if (cnTmp.length == 2)
				cn = cnTmp[1];
			else
				cn = cnTmp[0];
			String sn = id[1];
			String uid = ldap.searchAttribute(Config.get("USERS_BASE_DN", ""),
					cn, "sn=" + sn, "uid");
			ldap.close();
			return uid;
		} catch (Exception e) {
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
	  
	  public static boolean isPasswordValid(String pass) {
			LDAP ldap = new LDAP();
			try {
				String url = "ldap://"+ Config.get("LDAP_IP", "localhost")+":"+Config.get("LDAP_PORT", "389");

				ldap.initAuth(url,Config.get("LDAP_ADMIN_DN","cn=admin,dc=pkirepository,dc=org"), pass);
				
				ldap.close();
				return true;
			}
			catch(Exception e) {
				return false;
			}
	  }
}
