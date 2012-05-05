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
import org.bouncycastle.asn1.x509.X509Extensions;
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
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;



public class setup_ca_alt {
	private static final int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000;
    public static X509Certificate generateRootCert(KeyPair pair, String dn)
            throws Exception
    	{
    	    X509V1CertificateGenerator  certGen = new X509V1CertificateGenerator();
    	
    	    certGen.setSerialNumber(BigInteger.valueOf(1));
    	    certGen.setIssuerDN(new X500Principal("CN="+dn));//Test CA Certificate"));
    	    certGen.setNotBefore(new Date(System.currentTimeMillis()));
    	    certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
    	    certGen.setSubjectDN(new X500Principal("CN="+dn));//Test CA Certificate"));
    	    certGen.setPublicKey(pair.getPublic());
    	    certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
    	
    	    return certGen.generateX509Certificate(pair.getPrivate(), "BC");
    	}
        
        /**
         * Generate a sample V3 certificate to use as an intermediate CA certificate
         */
        public static X509Certificate generateIntermediateCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert,String dn)
            throws Exception
        {
            X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

            certGen.setSerialNumber(BigInteger.valueOf(1));
            certGen.setIssuerDN(caCert.getSubjectX500Principal());
            certGen.setNotBefore(new Date(System.currentTimeMillis()));
            certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
            certGen.setSubjectDN(new X500Principal("CN="+dn));//Test Intermediate Certificate"));
            certGen.setPublicKey(intKey);
            certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
        
            certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
            certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(intKey));
            certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
            certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

            return certGen.generateX509Certificate(caKey, "BC");
        }
        
        /**
         * Generate a sample V3 certificate to use as an end entity certificate
         */
        public static X509Certificate generateEndEntityCert(PublicKey entityKey, PrivateKey caKey, X509Certificate caCert,String dn)
    	    throws Exception
    	{
            X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

            certGen.setSerialNumber(BigInteger.valueOf(1));
            certGen.setIssuerDN(caCert.getSubjectX500Principal());
            certGen.setNotBefore(new Date(System.currentTimeMillis()));
            certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
            certGen.setSubjectDN(new X500Principal("CN="+dn));//Test End Certificate"));
            certGen.setPublicKey(entityKey);
            certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
            
            certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
            certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(entityKey));
            certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

            return certGen.generateX509Certificate(caKey, "BC");
    	}
	
	
	public static X509Certificate createSelfSignedCertificate(String issuer, String subj, KeyPair kp) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		
		String		subject = subj;
		KeyPair		keyPair = kp;
		String		issuerName = issuer;
		BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
		Date			notBefore = new Date(System.currentTimeMillis());
		Date			notAfter = new Date(System.currentTimeMillis()+1000*60*60);
		
		JcaX509v3CertificateBuilder builder  = null;
		
		X500Name subjectFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subject).build();
		X500Name issuerFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, issuerName).build();
		builder  = new JcaX509v3CertificateBuilder(issuerFormated, serialNumber, notBefore, notAfter, subjectFormated, keyPair.getPublic());

		//On crée le signataire qui sera la clé privé du CA
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate());//our own key
		
		// Pour le moment on autorise au CA que la signature de certificat et la signature de CRL (a priori il ne fera rien d'autre)
		KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
		builder.addExtension(X509Extension.keyUsage, false, keyUsage);
		
		ExtendedKeyUsage extendedKeyUsage  = new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage);
		builder.addExtension(X509Extension.extendedKeyUsage, false, extendedKeyUsage);
		
		GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, subject));
		builder.addExtension(X509Extension.subjectAlternativeName, false, subjectAltName);
		
		SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
		builder.addExtension(X509Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
		
		X509CertificateHolder holder = builder.build(contentSigner);
		
		return (X509Certificate) CertificateFactory.getInstance("X.509","BC").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
	}

	
	public static X509Certificate createSignedCertificate(String issuer, String subj, KeyPair kp, X509Certificate caCert, PrivateKey caKey) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
		Security.addProvider(new BouncyCastleProvider());
		
		String		subject = subj;
		KeyPair		keyPair = kp;
		String		issuerName = issuer;//caCert.getIssuerDN().getName();
		BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
		Date			notBefore = new Date(System.currentTimeMillis());
		Date			notAfter = new Date(System.currentTimeMillis()+1000*60*60);
		
		JcaX509v3CertificateBuilder builder  = null;
		
		X500Name subjectFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subject).build();
		X500Name issuerFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, issuerName).build();
		//builder  = new JcaX509v3CertificateBuilder(issuerFormated, serialNumber, notBefore, notAfter, subjectFormated, keyPair.getPublic());
		builder  = new JcaX509v3CertificateBuilder(caCert, serialNumber, notBefore, notAfter, new X500Principal("CN="+subject), keyPair.getPublic());
		
		//On crée le signataire qui sera la clé privé du CA
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(caKey);//our own key
		
		// Pour le moment on autorise au CA que la signature de certificat et la signature de CRL (a priori il ne fera rien d'autre)
		KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign|KeyUsage.digitalSignature);
		builder.addExtension(X509Extension.keyUsage, false, keyUsage);
		/*
		ExtendedKeyUsage extendedKeyUsage  = new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage);
		builder.addExtension(X509Extension.extendedKeyUsage, false, extendedKeyUsage);
		
		GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, subject));
		builder.addExtension(X509Extension.subjectAlternativeName, false, subjectAltName);
		*/
		SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
		builder.addExtension(X509Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
		
		// En +
		builder.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(0));
		builder.addExtension(X509Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCert));
		
		X509CertificateHolder holder = builder.build(contentSigner);
		
		return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
	}
	
	
	public static PKCS10CertificationRequest generate_csr(String name, KeyPair kp) throws NoSuchAlgorithmException, OperatorCreationException  {
        KeyPair keys = kp;
        
        X500Name subjectName = new X500Name("CN="+name);
       // PKCS10CertificationRequest kpGen = new PKCS10CertificationRequest("SHA1withRSA",keys.getPublic(),	null,	keys.getPrivate()); 
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());
        PKCS10CertificationRequestBuilder csrgen = new PKCS10CertificationRequestBuilder(subjectName, keyInfo);
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keys.getPrivate());//Un peu étrange qu'on utilise notre clé privée
        return csrgen.build(contentSigner);
	}
	
	
	
	public static X509Certificate retrieveCertificateFromCSR(PKCS10CertificationRequest inputCSR, PrivateKey caPrivate, X509Certificate caPublic) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, OperatorCreationException, CertificateException {   

	    AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder() .find("SHA1withRSA");
	    AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

	    AsymmetricKeyParameter parameterCa = PrivateKeyFactory.createKey(caPrivate.getEncoded());
	    SubjectPublicKeyInfo keyInfo = inputCSR.getSubjectPublicKeyInfo();

	    
	    X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(new X500Name(caPublic.getIssuerDN().getName()),
	    																																new BigInteger("1"),
	    																																new Date(System.currentTimeMillis()),
	    																																new Date(System.currentTimeMillis() + 30 * 365 * 24 * 60 * 60 * 1000),
	    																																inputCSR.getSubject(),
	    																																keyInfo);
	    //A modifier mettre le classique BcRSA ContentSigner ...
	    ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(parameterCa);        
	    
	    myCertificateGenerator.addExtension(X509Extension.subjectKeyIdentifier, false, inputCSR.getSubjectPublicKeyInfo());
	    
	    
	    
	    X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
	    /*
	    org.bouncycastle.asn1.x509.Certificate certificateStructure = holder.toASN1Structure(); 

	    java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509", "BC");

	    // Read Certificate
	    InputStream is1 = new ByteArrayInputStream(certificateStructure.getEncoded());
	    X509Certificate theCert = (X509Certificate) cf.generateCertificate(is1);
	    is1.close();
	    return theCert;*/
	    return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509","BC").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
	}
	
	
	
	
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		Security.addProvider(new BouncyCastleProvider());
		
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		
		try {
			ks.load(new FileInputStream("src/Playground/test_keystore_alt.ks"), "passwd".toCharArray());
		}
		catch (FileNotFoundException e) {
			System.out.println("First launch !");
			ks.load(null);
		}
		
		//############### CA Creation ################
		//Si le CA existe deja on le supprime
		if(ks.containsAlias("CA_Certificat"))
			ks.deleteEntry("CA_Certificat");
		if(ks.containsAlias("CA_Private"))
			ks.deleteEntry("CA_Private");
		
		//Crée le CA autosigné
		KeyPair		keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		X509Certificate caCert = null;
		try {
			caCert = createSelfSignedCertificate("CA Root", "CA Root", keyPair);
			//caCert = generateRootCert(keyPair,"Test CA Certificate");
			
			//Ajout le certificat et la clé privé du CA dans le keystore
			ks.setCertificateEntry("CA_Certificate", caCert);
			ks.setKeyEntry("CA_Private", keyPair.getPrivate(), "monpassCA".toCharArray(), new Certificate[] { caCert});
			System.out.println(caCert.toString());
		}
		catch (Exception e) { //Should catch all exception gently
			System.out.println("An error occured ! in CA Creation");
			e.printStackTrace();
		}
		//########################################
		
		
		//############## CA Intermediaire ###############
		if(ks.containsAlias("CA_Intermediaire_Certificate"))
			ks.deleteEntry("CA_Intermediaire_Certificate");
		if(ks.containsAlias("CA_Intermediaire_Private"))
			ks.deleteEntry("CA_Intermediaire_Private");
		
		//Crée le CA autosigné
		KeyPair		keyPairInt = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		try {
			//X509Certificate intCert = createSignedCertificate("Robin Corp CA", "CA Intermediaire", keyPairInt, caCert, keyPair.getPrivate()); //Un peu dégeulasse mais pour le test
			X509Certificate intCert = createSignedCertificate("CA Root", "Test Intermediate Certificate", keyPairInt, caCert, keyPair.getPrivate()); //Un peu dégeulasse mais pour le test
			//X509Certificate intCert = generateIntermediateCert(keyPairInt.getPublic(), keyPair.getPrivate(), caCert, "Test Intermediate Certificate");
			
			//Ajout le certificat et la clé privé du CA dans le keystore
			ks.setCertificateEntry("CA_Intermediaire_Certificate", intCert);
			ks.setKeyEntry("CA_Intermediaire_Private", keyPairInt.getPrivate(), "monpassInt".toCharArray(), new Certificate[] { caCert, intCert});
			
		}
		catch (Exception e) { //Should catch all exception gently
			System.out.println("An error occured ! in CA Intermediaire Creation");
			e.printStackTrace();
		}		
		//########################################
		
		
		//############ Creation Personne 1 ##############
		// Si personne1 existe on la retire du keystore
		if(ks.containsAlias("personne1_certificat"))
			ks.deleteEntry("personne1_certificat");
		if(ks.containsAlias("personne1_private"))
			ks.deleteEntry("personne1_private");
		
		//Créer une CSR pour personne1
		try {
			KeyPair		keyPairPersonne1 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
			PrivateKey privInt = (PrivateKey) ks.getKey("CA_Intermediaire_Private", "monpassInt".toCharArray());
			X509Certificate pubInt = (X509Certificate) ks.getCertificate("CA_Intermediaire_Certificate");
			/*
			PKCS10CertificationRequest personne1_csr = generate_csr("Personne1 Certificat Personnel", keyPairPersonne1);
			
			//Fait signer la CSR par le CA (opération normalement faite par le CA)
			
			X509Certificate personne1_certificat = retrieveCertificateFromCSR(personne1_csr, privInt, pubInt);
			*/
			X509Certificate personne1_certificat = createSignedCertificate("Test Intermediate Certificate", "Test End Certificate", keyPairPersonne1, pubInt, privInt);
			//X509Certificate personne1_certificat = generateEndEntityCert(keyPairPersonne1.getPublic(), privInt, pubInt,"Test End Certificate");
			
			//Ajout le certificat et la clé privé de personne1
			ks.setCertificateEntry("personne1_certificat", personne1_certificat);
			Certificate[] chain = ks.getCertificateChain("CA_Intermediaire_Private");
			
			Certificate[] newchain = new Certificate[chain.length+1];
			for(int i=0; i < chain.length ; i ++)
				newchain[i] = chain[i];
			newchain[chain.length] = personne1_certificat;
			
			ks.setKeyEntry("personne1_private", keyPairPersonne1.getPrivate(), "monpassP1".toCharArray(), newchain);
			
			//CertPath certpath = CertificateFactory.getInstance("X.509", "BC").generateCertPath(Arrays.asList(chain));
			
			//System.out.println(personne1_certificat.toString());
		} catch (Exception e) {
			System.out.println("An error occured in Personne 1 Creation");
			e.printStackTrace();
		}
		//#########################################

		
		//############ Creation Personne 2 ##############
		// Si personne2 existe on la retire du keystore
		if(ks.containsAlias("personne2_certificat"))
			ks.deleteEntry("personne2_certificat");
		if(ks.containsAlias("personne2_private"))
			ks.deleteEntry("personne2_private");
		
		//Créer une CSR pour personne2
		try {
			KeyPair		keyPairPersonne2 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
			PKCS10CertificationRequest personne2_csr = generate_csr("Personne2 Certificat Personnel", keyPairPersonne2);
			
			//Fait signer la CSR par le CA (opération normalement faite par le CA)
			PrivateKey privInt = (PrivateKey) ks.getKey("CA_Intermediaire_Private", "monpassInt".toCharArray());
			X509Certificate pubInt = (X509Certificate) ks.getCertificate("CA_Intermediaire_Certificate");
			
			X509Certificate personne2_certificat = retrieveCertificateFromCSR(personne2_csr, privInt, pubInt);
			
			//Ajout le certificat et la clé privé de personne2
			ks.setCertificateEntry("personne2_certificat", personne2_certificat);
			Certificate[] chain = ks.getCertificateChain("CA_Intermediaire_Private");
			
			Certificate[] newchain = new Certificate[chain.length+1];
			for(int i=0; i < chain.length ; i ++)
				newchain[i] = chain[i];
			newchain[chain.length] = personne2_certificat;
			
			ks.setKeyEntry("personne2_private", keyPairPersonne2.getPrivate(), "monpassP2".toCharArray(), newchain);
			
			//CertPath certpath = CertificateFactory.getInstance("X.509", "BC").generateCertPath(Arrays.asList(chain));
			
			//System.out.println(personne2_certificat.toString());
		} catch (Exception e) {
			System.out.println("An error occured in Personne 2 Creation");
			e.printStackTrace();
		}
		//#########################################
		
		ks.store(new FileOutputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());
	}
}
