package Playground;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class creation_certificat {
	
	// Pour creation de certificat X509V1 -> donc inutile
	public static X509Certificate createCertificate() throws NoSuchAlgorithmException, CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, SignatureException {
		Security.addProvider(new BouncyCastleProvider());
		
		// Informations about the key
		Calendar cal = Calendar.getInstance();
		Date startDate = cal.getTime();
		cal.add(Calendar.YEAR, +1);
		Date expireDate = cal.getTime();
		BigInteger serialNumber = BigInteger.valueOf(1);
		
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        KeyPair keys = keygen.generateKeyPair();
        //--------------------------------------
        
        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        X500Principal  dnName = new X500Principal("CN=Test CA Certificate");

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(dnName);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expireDate);
        certGen.setSubjectDN(dnName);                       // note: same as issuer
        certGen.setPublicKey(keys.getPublic());
        certGen.setSignatureAlgorithm("SHA1withRSA");

        X509Certificate cert = certGen.generate(keys.getPrivate(), "BC");
        
        return cert;
	}
	
	//Creation de certificat V3 (avec methodes depreciées) -> inutile
	public static void createCertificateV3() throws CertificateParsingException, IOException, CertificateEncodingException, NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, NoSuchProviderException, SignatureException {
		Security.addProvider(new BouncyCastleProvider());
		
		X509Certificate caCert = null; // Should normally be the CA certificate
		PublicKey publicKey = null; // used for Subject key identifier
		PrivateKey cakey = null;
		
		//AuthorityKeyIdentifier: The AuthorityKeyIdentifier extension provides a means for identifying the issuer of the certificate. You can think of it as the equivalent to a pointer to the parent certificate.
		X509Extension extention = new X509Extension(false, new DEROctetString(new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCert)));
		
		//BasicConstraints: The BasicConstraints identifies whether the certificate is that of a CA, and optionally it indicates how many certificates after the next one can follow it in the certificate path
		X509Extension extension2 = new X509Extension(true, new DEROctetString(new BasicConstraints(true)));
		
		//ExtendedKeyUsage: ExtendedKeyUsage is an extension which restricts a certificate to a specific usage, given by the object identifiers it contains which are KeyPurposeIds.
		ExtendedKeyUsage extendedKeyUsage  = new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage); //!! Can limit to OCSP code signing etc..
		X509Extension extension3 = new X509Extension(false, new DEROctetString(extendedKeyUsage));
		
		//KeyUsageExtension: This extension is also used to restrict the purposes that a certificate can be put to.
		KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign); //il y en a plein d'autres
		X509Extension extension4 = new X509Extension(true, new DEROctetString(keyUsage));
		
		//SubjectAlternativeName: SubjectAlternativeName extension is used to associate other names, such as email addresses with the DN giving the subject of the certificate.
		GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, "example@example.org"));
		X509Extension extension5 = new X509Extension(false, new DEROctetString(subjectAltName));
		
		//SubjectKeyIdentifier: The SubjectKeyIdentifier provides another means of identifying that a certificate contains a particular public key.
		X509Extension extension6 = new X509Extension(false, new DEROctetString(new JcaX509ExtensionUtils().createTruncatedSubjectKeyIdentifier(publicKey)));
	
	
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator(); //Use X509v3CertificateBuilder
		
		// Same as in V1
		
		certGen.addExtension("Element1", false, extention.getParsedValue());
		//..........
	
		X509Certificate cert = certGen.generate(cakey,"BC"); //caCert should be the private key of the CA
	}
 	
	
	//La vrai version qui déchire tout
	public static void createCertificateV3new() throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
		Security.addProvider(new BouncyCastleProvider());
		
		String	DEFAULT_ISSUER	= "Robin Corp";
		String						subject = "My Subject";
		KeyPair						keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		Signature				signType;
		String						issuerName = DEFAULT_ISSUER;
		Certificate					issuerCertificate = null; //Should be the issuer certificate (in which will be retrieve the subject or whatever)
		PrivateKey				issuerPrivateKey = keyPair.getPrivate(); // ########## Should be the CA private key !
		BigInteger					serialNumber = BigInteger.valueOf(System.currentTimeMillis());
		Date						notBefore = new Date(System.currentTimeMillis());
		Date						notAfter = new Date(System.currentTimeMillis()+1000*60*60);
		
		JcaX509v3CertificateBuilder builder  = null;
		
		
		if (issuerCertificate != null) {
			X500Principal subjectFormated = new X500Principal(new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subject).build().getEncoded());
			builder = new JcaX509v3CertificateBuilder((X509Certificate) issuerCertificate, serialNumber, notBefore, notAfter, subjectFormated, keyPair.getPublic());
		}
		else {
			X500Name subjectFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subject).build();
			X500Name issuerFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, issuerName).build();
			builder  = new JcaX509v3CertificateBuilder(issuerFormated, serialNumber, notBefore, notAfter, subjectFormated, keyPair.getPublic());
		}
		// Maintenant notre builder est initialisé !
		
		//On crée le signataire qui sera la clé privé du CA
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(issuerPrivateKey);
		
		
		// On ajoute les extensions si besoins !
		KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign); //il y en a plein d'autres
		builder.addExtension(X509Extension.keyUsage, false, keyUsage);
		
		ExtendedKeyUsage extendedKeyUsage  = new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage);
		builder.addExtension(X509Extension.extendedKeyUsage, false, extendedKeyUsage);
		
		GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, subject));
		builder.addExtension(X509Extension.subjectAlternativeName, false, subjectAltName);
		
		SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
		builder.addExtension(X509Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
		
		X509CertificateHolder holder = builder.build(contentSigner);
		
		X509Certificate certificate = (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
		PrivateKey privateKey = keyPair.getPrivate();
		
		//rivateKeyHolder privateKeyHolder = new PrivateKeyHolder(privateKey, new Certificate[] { certificate });
		System.out.println(certificate.toString());
	}
	
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		try {
			createCertificateV3new();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
}
