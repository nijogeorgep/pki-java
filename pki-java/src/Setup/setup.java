package Setup;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;

import org.bouncycastle.cert.X509CRLHolder;

import Ldap.ldaputils;
import Utils.Config;
import Utils.PasswordUtils;

import Clients.ClientUtils;
import CryptoAPI.CRLManager;
import CryptoAPI.CertificateManager;

public class setup {
	
	Properties prop;
	KeyStore ks;
	String path;
	String pass;
	String password;
	String aliasC;
	String aliasK;
	String crlrooturl;
	String crlurl;
	String ocspurl;
	
	public setup() throws Exception {
		prop = new Properties();
	    InputStream is = new FileInputStream(Config.file);
	    prop.load(is);
	    String ldapip = Config.get("LDAP_IP","localhost");
	    String ldapport = Config.get("LDAP_PORT","389");
	    String repoip = Config.get("IP_REPOSITORY","localhost");
	    String repoport = Config.get("PORT_REPOSITORY", "7003");
	    this.crlrooturl = "ldap://" + ldapip +":" + ldapport +"/ou=rootCA," + Config.get("LDAP_ROOT_DN","dc=pkirepository,dc=org");
	    this.crlurl = "ldap://" + ldapip + ":" + ldapport + "/" + Config.get("USERS_BASE_DN","");
	    this.ocspurl = "http://" + repoip + ":" + repoport;
	}

	
	public void run() throws Exception {
		int c2 = 0;
		int choice = makeChoice("Configure CA,RA and Repository ?", "Yes", "No");
		if (choice == 1) {
			password = PasswordUtils.readInPassword("LDAP :");
			if(!ldaputils.isPasswordValid(password)) {
				System.out.println("Password wrong for the configured LDAP");
				System.exit(1);
			}
			else
				System.out.println("Password OK");
			
			//------ CA Creation -------
			openKeyStore("CA");
			//If the CA already exists then delete it
			aliasC = Config.get("KS_ALIAS_CERT_CA","CA_Certificate");
			aliasK = Config.get("KS_ALIAS_KEY_CA", "CA_Private");
			removeAlias(aliasC);
			removeAlias(aliasK);

			//Create the self signed CA
			KeyPair		keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
			X509Certificate caCert =  CertificateManager.createSelfSignedCertificate("CA Root", keyPair, this.crlrooturl, this.ocspurl);
				
			//Add the certificate and the private key of the CA in the Keystor
			ks.setCertificateEntry(aliasC, caCert);
			ks.setKeyEntry(aliasK, keyPair.getPrivate(), Config.get("PASSWORD_CA_ROOT","").toCharArray(), new Certificate[] { caCert});
			ldaputils.setCertificateCA(caCert, "ou=rootCA,dc=pkirepository,dc=org",password);
			X509CRLHolder crlroot = CRLManager.createCRL(caCert, keyPair.getPrivate());
			ldaputils.setCRL(crlroot,  "ou=rootCA,dc=pkirepository,dc=org",password);
			//-----------------------------
			
			//------- CA CRL OCSP --------
			String aliasSigC = Config.get("KS_ALIAS_CERT_CA_SIG","CA_SigningOnly_Certificate");
			String aliasSigK = Config.get("KS_ALIAS_KEY_CA_SIG", "CA_SigningOnly_Private");
			removeAlias(aliasSigC);
			removeAlias(aliasSigK);

			KeyPair		keyPairSig = KeyPairGenerator.getInstance("RSA").generateKeyPair();

			X509Certificate sigPub = CertificateManager.createSignedCertificateIntermediaire("CA Root", "CA CRL OCSP Signing", keyPairSig, caCert, keyPair.getPrivate(),BigInteger.valueOf(1), this.crlurl,this.ocspurl);
			
			ldaputils.setCertificateCA(caCert, "ou=signingCA,ou=rootCA,dc=pkirepository,dc=org",password);
			ks.setCertificateEntry(aliasSigC, sigPub);
			ks.setKeyEntry(aliasSigK, keyPairSig.getPrivate(),Config.get("PASSWORD_CA_SIG","").toCharArray(), new Certificate[] { caCert, sigPub});
			//-----------------------------------------------
			
			//------- CA Intermediaire People --------
			String aliasPeopleC = Config.get("KS_ALIAS_CERT_CA_INTP","CA_IntermediairePeople_Certificate");
			String aliasPeopleK = Config.get("KS_ALIAS_KEY_CA_INTP","CA_IntermediairePeople_Private");
			removeAlias(aliasPeopleC);
			removeAlias(aliasPeopleK);

			KeyPair		keyPairInt = KeyPairGenerator.getInstance("RSA").generateKeyPair();

			X509Certificate intCert = CertificateManager.createSignedCertificateIntermediaire("CA Root", "CA Intermediaire People", keyPairInt, caCert, keyPair.getPrivate(),BigInteger.valueOf(1),this.crlurl,this.ocspurl);

			ks.setCertificateEntry(aliasPeopleC, intCert);
			ks.setKeyEntry(aliasPeopleK, keyPairInt.getPrivate(),Config.get("PASSWORD_CA_INTP","").toCharArray(), new Certificate[] { caCert, intCert});
			ldaputils.setCertificateCA(caCert, "ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org",password);
			X509CRLHolder crl = CRLManager.createCRL(sigPub, keyPairSig.getPrivate());
			ldaputils.setCRL(crl,  "ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org",password);
			//------------------------------------

			//------- CA Intermediaire Server --------
			String aliasServerC = Config.get("KS_ALIAS_CERT_CA_INTS","CA_IntermediaireServer_Certificate");
			String aliasServerK = Config.get("KS_ALIAS_KEY_CA_INTS","CA_IntermediaireServer_Private");
			removeAlias(aliasServerC);
			removeAlias(aliasServerK);

			KeyPair		keyPairIntS = KeyPairGenerator.getInstance("RSA").generateKeyPair();

			X509Certificate intCertS = CertificateManager.createSignedCertificateIntermediaire("CA Root", "CA Intermediaire Server", keyPairIntS, caCert, keyPair.getPrivate(),BigInteger.valueOf(1),this.crlurl,this.ocspurl);

			ks.setCertificateEntry(aliasServerC, intCert);
			ks.setKeyEntry(aliasServerK, keyPairInt.getPrivate(),Config.get("PASSWORD_CA_INTS","").toCharArray(), new Certificate[] { caCert, intCertS});
			ldaputils.setCertificateCA(caCert, "ou=intermediateServerCA,ou=rootCA,dc=pkirepository,dc=org",password);
			X509CRLHolder crlserv = CRLManager.createCRL(sigPub, keyPairSig.getPrivate());
			ldaputils.setCRL(crlserv,  "ou=intermediateServerCA,ou=rootCA,dc=pkirepository,dc=org",password);
			//-----------------------------------------------
			
			saveKeyStore(); //Now the keystore of the CA is filled
			
			openKeyStore("RA");
			ks.setCertificateEntry(aliasSigC, sigPub);
			ks.setKeyEntry(aliasSigK, keyPairSig.getPrivate(),Config.get("PASSWORD_CA_SIG","").toCharArray(), new Certificate[] { caCert, sigPub});
			saveKeyStore();
			
			openKeyStore("REPOSITORY");
			ks.setCertificateEntry(aliasSigC, sigPub);
			ks.setKeyEntry(aliasSigK, keyPairSig.getPrivate(),Config.get("PASSWORD_CA_SIG","").toCharArray(), new Certificate[] { caCert, sigPub});
			saveKeyStore();
			c2 = makeChoice("Configure Client ?","Yes", "No");
			if (c2 == 1) { // If the user decide to configure the client here certificates are directly added
					openKeyStore("USER");
					ks.setCertificateEntry(aliasSigC, sigPub);
					ks.setCertificateEntry(aliasC, caCert);
					ks.setCertificateEntry(aliasPeopleC, intCert);
					saveKeyStore();
			}
		}//------------------ Fin configuration CA ---------------------
		
		if (c2 == 0) {
			c2 = makeChoice("Configure Client ?","Yes", "No");
			if (c2 == 1) { // If the user decide to configure here certificate will be downloaded on the LDAP
				openKeyStore("USER");
				String aliasSigC = Config.get("KS_ALIAS_CERT_CA_SIG","CA_SigningOnly_Certificate");
				String aliasPeopleC = Config.get("KS_ALIAS_CERT_CA_INTP","CA_IntermediairePeople_Certificate");
				String aliasC = Config.get("KS_ALIAS_CERT_CA","CA_Certificate");
				X509Certificate caSig = ldaputils.getCaCertificate("ou=rootCA,dc=pkirepository,dc=org", "signingCA");
				X509Certificate caRoot = ldaputils.getCaCertificate("dc=pkirepository,dc=org", "rootCA");
				X509Certificate caInt = ldaputils.getCaCertificate("ou=rootCA,dc=pkirepository,dc=org", "intermediatePeopleCA");
				ks.setCertificateEntry(aliasSigC, caSig);
				ks.setCertificateEntry(aliasC, caRoot);
				ks.setCertificateEntry(aliasPeopleC, caInt);
				saveKeyStore();
			}
		}
		System.out.println("End.");
	}
	
	public void openKeyStore(String entity) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		// Generic method to open a keystore
		ks = KeyStore.getInstance(KeyStore.getDefaultType());
		
		path = Config.get("KS_PATH_"+entity,"keystores/"+entity.toLowerCase()+"_keystore.ks");
		pass = Config.get("KS_PASS_"+entity, "passwd");
		File f = new File(path);
		if (!(f.exists())) {
			f.getParentFile().mkdirs();
		}
		try {
			ks.load(new FileInputStream(path), pass.toCharArray());
		}
		catch (FileNotFoundException e) {
			ks.load(null);
		}
	}
	
	public void saveKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		ks.store(new FileOutputStream(path), pass.toCharArray());
	}
	
	public void removeAlias(String alias) throws KeyStoreException {
		if(ks.containsAlias(alias))
			ks.deleteEntry(alias);
	}
	
	
	  public int makeChoice(String title, String choice1, String choice2){
			Integer val = null;
			boolean isOK = true;
			try {
				
				do {
				    System.out.println(title);
				    System.out.println("1 - "+choice1);
				    System.out.println("2 - "+choice2);
				    val = ClientUtils.readIntKeyboard();
				    if(val == null)
				    	continue;
				    else
				    	if(val >= 1 && val <=2)
				    		isOK= false;
				}while (isOK);
			}
			catch(Exception e) {
				e.printStackTrace();
			}
			return val;
	  }
	
	public static void main(String[] args) throws Exception {
		Config.checkConfigFile();
		setup setup = new setup();
		setup.run();
	}
}
