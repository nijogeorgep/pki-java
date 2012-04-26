package Playground;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import CryptoAPI.CRLManager;
import CryptoAPI.CSRManager;
import CryptoAPI.CertificateManager;
import Ldap.ldaputils;
import Utils.Config;

public class setup_ca {
	
	public static void removeAlias(KeyStore ks, String alias) throws KeyStoreException {
		if(ks.containsAlias(alias))
			ks.deleteEntry(alias);
	}
	
	public static Certificate[] createNewChain(Certificate[] chain, X509Certificate cert) {
		Certificate[] newchain = new Certificate[chain.length+1];
		for(int i=0; i < chain.length ; i ++)
			newchain[i] = chain[i];
		newchain[chain.length] = cert;
		return newchain;
	}
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		
		try {
			ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());
		}
		catch (FileNotFoundException e) {
			System.out.println("First launch !");
			ks.load(null);
		}
		
		//------ CA Creation -------
		//Si le CA existe deja on le supprime
		removeAlias(ks,"CA_Certificat");
		removeAlias(ks,"CA_Private");

		//Crée le CA autosigné
		KeyPair		keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		X509Certificate caCert =  CertificateManager.createSelfSignedCertificate("CA Root", keyPair);
			
		//Ajout le certificat et la clé privé du CA dans le keystore
		ks.setCertificateEntry("CA_Certificate", caCert);
		ks.setKeyEntry("CA_Private", keyPair.getPrivate(), Config.get("PASSWORD_CA_ROOT","").toCharArray(), new Certificate[] { caCert});
		ldaputils.setCertificateCA(caCert, "ou=rootCA,dc=pkirepository,dc=org");
		X509CRLHolder crlroot = CRLManager.createCRL(caCert, keyPair.getPrivate());
		ldaputils.setCRL(crlroot,  "ou=rootCA,dc=pkirepository,dc=org");
		//-----------------------------
		
		//------- CA CRL OCSP --------
		removeAlias(ks,"CA_SigningOnly_Certificate");
		removeAlias(ks,"CA_SigningOnly_Private");

		//Crée le CA autosigné
		KeyPair		keyPairSig = KeyPairGenerator.getInstance("RSA").generateKeyPair();

		X509Certificate sigPub = CertificateManager.createSignedCertificateIntermediaire("CA Root", "CA CRL OCSP Signing", keyPairSig, caCert, keyPair.getPrivate(),BigInteger.valueOf(1));
		
		//Ajout le certificat et la clé privé du CA dans le keystore
		ks.setCertificateEntry("CA_SigningOnly_Certificate", sigPub);
		ks.setKeyEntry("CA_SigningOnly_Private", keyPairSig.getPrivate(),Config.get("PASSWORD_CA_SIG","").toCharArray(), new Certificate[] { caCert, sigPub});
		//Il ne faut pas le mettre dans le keystore du CA mais dans celui du Repository
		//-----------------------------------------------
		
		
		//------- CA Intermediaire People --------
		removeAlias(ks,"CA_IntermediairePeople_Certificate");
		removeAlias(ks,"CA_IntermediairePeople_Private");

		//Crée le CA autosigné
		KeyPair		keyPairInt = KeyPairGenerator.getInstance("RSA").generateKeyPair();

		X509Certificate intCert = CertificateManager.createSignedCertificateIntermediaire("CA Root", "CA Intermediaire People", keyPairInt, caCert, keyPair.getPrivate(),BigInteger.valueOf(1));
		
		//Ajout le certificat et la clé privé du CA dans le keystore
		ks.setCertificateEntry("CA_IntermediairePeople_Certificate", intCert);
		ks.setKeyEntry("CA_IntermediairePeople_Private", keyPairInt.getPrivate(),Config.get("PASSWORD_CA_INTP","").toCharArray(), new Certificate[] { caCert, intCert});
		ldaputils.setCertificateCA(caCert, "ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org");
		X509CRLHolder crl = CRLManager.createCRL(sigPub, keyPairSig.getPrivate());
		ldaputils.setCRL(crl,  "ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org");
		//------------------------------------

		//------- CA Intermediaire Server --------
		removeAlias(ks,"CA_IntermediaireServer_Certificate");
		removeAlias(ks,"CA_IntermediaireServer_Private");

		//Crée le CA autosigné
		KeyPair		keyPairIntS = KeyPairGenerator.getInstance("RSA").generateKeyPair();

		X509Certificate intCertS = CertificateManager.createSignedCertificateIntermediaire("CA Root", "CA Intermediaire Server", keyPairIntS, caCert, keyPair.getPrivate(),BigInteger.valueOf(1));
		
		//Ajout le certificat et la clé privé du CA dans le keystore
		ks.setCertificateEntry("CA_IntermediaireServer_Certificate", intCert);
		ks.setKeyEntry("CA_IntermediaireServer_Private", keyPairInt.getPrivate(),Config.get("PASSWORD_CA_INTS","").toCharArray(), new Certificate[] { caCert, intCertS});
		ldaputils.setCertificateCA(caCert, "ou=intermediateServerCA,ou=rootCA,dc=pkirepository,dc=org");
		X509CRLHolder crlserv = CRLManager.createCRL(sigPub, keyPairSig.getPrivate());
		ldaputils.setCRL(crlserv,  "ou=intermediateServerCA,ou=rootCA,dc=pkirepository,dc=org");
		//-----------------------------------------------
		
		
		
		//------- Creation Personne 1 -------
		// Si personne1 existe on la retire du keystore
		removeAlias(ks, "personne1_certificat");
		removeAlias(ks,"personne1_private");

		//Créer une CSR pour personne1
		KeyPair		keyPairPersonne1 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		
		PKCS10CertificationRequest personne1_csr = CSRManager.generate_csr("Personne1 Certificat Personnel", keyPairPersonne1);
		
		//Fait signer la CSR par le CA (opération normalement faite par le CA)
		X509Certificate personne1_certificat = CSRManager.retrieveCertificateFromCSR(personne1_csr, keyPairInt.getPrivate(), intCert,BigInteger.ONE);

		//Ajout le certificat et la clé privé de personne1
		ks.setCertificateEntry("personne1_certificat", personne1_certificat);
		Certificate[] chain = ks.getCertificateChain("CA_Intermediaire_Private");

		ks.setKeyEntry("personne1_private", keyPairPersonne1.getPrivate(), "monpassP1".toCharArray(), createNewChain(chain, personne1_certificat));
		//--------------------------------------
		
		
		ks.store(new FileOutputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());
	}
}
