package CryptoAPI;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
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

public class CertificateManager {
	
	public static X509Certificate createSelfSignedCertificate(String subj, KeyPair kp) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
		/* EXTENSION:												CRITICAL
		 * basicConstraints(true) pathlen(1)				true
		 * authorityKeyIdentifier(pas utile)
		 * subjectKeyIdentifier:hash							false
		 * KeyUsage: keyCertSign
		 * 
		 * EXTENDEDKeyUsage
		 * nsComment:"PKI Root Certificate"
		 * cRLDistributionPoint  ldap://localhost.org/RootCA/crl.crl
		 * authorityInfoAccess: http://ocsp.localhost.org
		 */
		Security.addProvider(new BouncyCastleProvider());
		
		String		subject = subj;
		KeyPair		keyPair = kp;
		String		issuerName = subj; //!! Issuer same as subject
		BigInteger serialNumber = BigInteger.ONE;
		
		Calendar cal = Calendar.getInstance();
		Date	notBefore = cal.getTime();
		cal.add(Calendar.YEAR, 1);
		Date notAfter = cal.getTime();
		
		JcaX509v3CertificateBuilder builder  = null;
		
		X500Name subjectFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subject).build();
		X500Name issuerFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, issuerName).build();
		builder  = new JcaX509v3CertificateBuilder(issuerFormated, serialNumber, notBefore, notAfter, subjectFormated, keyPair.getPublic());

		//On crée le signataire qui sera la clé privé du CA
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate());//our own key
		
		
		//------------------------- Extensions ------------------------
		builder.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(1)); //doit aussi être critique
		
		SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
		builder.addExtension(X509Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
		
		// Pour le moment on autorise au CA que la signature de certificat et la signature de CRL (a priori il ne fera rien d'autre)
		KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
		builder.addExtension(X509Extension.keyUsage, true, keyUsage); //KeyUsage doit être critique
		
		ExtendedKeyUsage extendedKeyUsage  = new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage);
		builder.addExtension(X509Extension.extendedKeyUsage, false, extendedKeyUsage);
		
		
		String url = "ldap://87.98.166.65:389/ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org";
		GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(url));
		GeneralNames gns = new GeneralNames(gn);
		DistributionPointName dpn = new DistributionPointName(gns);
		DistributionPoint distp = new DistributionPoint(dpn, null, null);
		DERSequence seq = new DERSequence(distp);
		builder.addExtension(X509Extension.cRLDistributionPoints, false, seq);
        //builder.addExtension(X509Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] { point }));
		
		url = "http://87.98.166.65:80";
		gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(url));
		AuthorityInformationAccess acc = new AuthorityInformationAccess(X509Extension.authorityInfoAccess, gn);
		builder.addExtension(X509Extension.authorityInfoAccess, false, acc);
		
		//GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, subject));
		///builder.addExtension(X509Extension.subjectAlternativeName, false, subjectAltName);
		//----------------------------------------------------------------
		
		X509CertificateHolder holder = builder.build(contentSigner);
		
		return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
	}

	
	public static X509Certificate createSignedCertificateIntermediaire(String issuer, String subj, KeyPair kp, X509Certificate caCert, PrivateKey caKey, BigInteger serial) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
		/* EXTENSION:																CRITICAL
		 * basicConstraint(true)pathlen:0									true
		 * authorityKeyIdentifier keyid:always, issuer:always		false
		 * subjectKeyIdentifier:hash											false
		 * KeyUsage: KeyCertSign
		 * 
		 * ExtendedKeyUsage:
		 * nsComment: "Intermediate CA for Users Cert"
		 * cRLDistributionPoint  ldap://localhost.org/RootCA/crl.crl
		 * authorityInfoAccess: http://ocsp.localhost.org
		 */
		Security.addProvider(new BouncyCastleProvider());
		
		String		subject = subj;
		KeyPair		keyPair = kp;
		String		issuerName = issuer;//caCert.getIssuerDN().getName();
		BigInteger serialNumber = serial;  // Here should take the next one !
		Calendar cal = Calendar.getInstance();
		Date	notBefore = cal.getTime();
		cal.add(Calendar.YEAR, 1);
		Date notAfter = cal.getTime();
		
		JcaX509v3CertificateBuilder builder  = null;
		
		//X500Name subjectFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subject).build();
		X500Name subjectFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subject).build();
		X500Name issuerFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, issuerName).build();
		builder  = new JcaX509v3CertificateBuilder(caCert, serialNumber, notBefore, notAfter, new X500Principal("CN="+subject), keyPair.getPublic());

		//On crée le signataire qui sera la clé privé du CA
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(caKey);//our own key
		
		
		//------------------------- Extensions ------------------------
		builder.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(0)); //doit aussi être critique
		
		builder.addExtension(X509Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCert));
		
		SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
		builder.addExtension(X509Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
		
		// Pour le moment on autorise au CA que la signature de certificat et la signature de CRL (a priori il ne fera rien d'autre)
		KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
		builder.addExtension(X509Extension.keyUsage, true, keyUsage); //KeyUsage doit être critique
		
		String url = "http://87.98.166.65:389/ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org";
		GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(url));
		GeneralNames gns = new GeneralNames(gn);
		DistributionPointName dpn = new DistributionPointName(gns);
		DistributionPoint distp = new DistributionPoint(dpn, null, null);
		DERSequence seq = new DERSequence(distp);
		builder.addExtension(X509Extension.cRLDistributionPoints, false, seq);
        //builder.addExtension(X509Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] { point }));
		
		url = "http://87.98.166.65:80";
		gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(url));
		AuthorityInformationAccess acc = new AuthorityInformationAccess(X509Extension.authorityInfoAccess, gn);
		builder.addExtension(X509Extension.authorityInfoAccess, false, acc);
		
		//GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, subject));
		///builder.addExtension(X509Extension.subjectAlternativeName, false, subjectAltName);
		//----------------------------------------------------------------

		X509CertificateHolder holder = builder.build(contentSigner);
		
		return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
	}
	
	
	
	public static X509Certificate createSignedCertificateOCSPAndCRL(String issuer, String subj, KeyPair kp, X509Certificate caCert, PrivateKey caKey, BigInteger serial) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
		/* EXTENSION:																	CRITICAL
		 * basicConstraints(false)													true
		 * authorityKeyIdentifier keyid:always
		 * subjectKeyIdentifier:hash
		 * keyUsage: cRLSign, digitalSignature, nonRepudiation 
		 * extendedKeyUsage: OCSPSigning									false
		 * nsComment "Certificate for CRL and OCSP Signing"
		 * cRLDistributionPoint  ldap://localhost.org/RootCA/crl.crl
		 * authorityInfoAccess: http://ocsp.localhost.org
		 */
		Security.addProvider(new BouncyCastleProvider());
		
		String		subject = subj;
		KeyPair		keyPair = kp;
		String		issuerName = issuer;//caCert.getIssuerDN().getName();
		BigInteger serialNumber = serial;  // Here should take the next one !
		Calendar cal = Calendar.getInstance();
		Date	notBefore = cal.getTime();
		cal.add(Calendar.YEAR, 1);
		Date notAfter = cal.getTime();
		
		JcaX509v3CertificateBuilder builder  = null;
		
		//X500Name subjectFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subject).build();
		X500Name subjectFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subject).build();
		X500Name issuerFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, issuerName).build();
		builder  = new JcaX509v3CertificateBuilder(caCert, serialNumber, notBefore, notAfter, new X500Principal("CN="+subject), keyPair.getPublic());

		//On crée le signataire qui sera la clé privé du CA
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(caKey);//our own key
		
		
		//------------------------- Extensions ------------------------
		builder.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(false)); //doit aussi être critique
		
		builder.addExtension(X509Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCert));
		
		SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
		builder.addExtension(X509Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
		
		// Pour le moment on autorise au CA que la signature de certificat et la signature de CRL (a priori il ne fera rien d'autre)
		KeyUsage keyUsage = new KeyUsage(KeyUsage.cRLSign | KeyUsage.digitalSignature | KeyUsage.nonRepudiation);
		builder.addExtension(X509Extension.keyUsage, true, keyUsage); //KeyUsage doit être critique
		
		ExtendedKeyUsage extendedKeyUsage  = new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning);
		builder.addExtension(X509Extension.extendedKeyUsage, false, extendedKeyUsage);
		
		String url = "http://87.98.166.65:389/ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org";
		GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(url));
		GeneralNames gns = new GeneralNames(gn);
		DistributionPointName dpn = new DistributionPointName(gns);
		DistributionPoint distp = new DistributionPoint(dpn, null, null);
		DERSequence seq = new DERSequence(distp);
		builder.addExtension(X509Extension.cRLDistributionPoints, false, seq);
        //builder.addExtension(X509Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] { point }));
		
		url = "http://87.98.166.65:80";
		gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(url));
		AuthorityInformationAccess acc = new AuthorityInformationAccess(X509Extension.authorityInfoAccess, gn);
		builder.addExtension(X509Extension.authorityInfoAccess, false, acc);
		
		//GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, subject));
		///builder.addExtension(X509Extension.subjectAlternativeName, false, subjectAltName);
		//----------------------------------------------------------------

		X509CertificateHolder holder = builder.build(contentSigner);
		
		return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
	}
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException {
		KeyPair		keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		X509Certificate caCert = createSelfSignedCertificate("CA Root", keyPair);
		X509Certificate intCert = createSignedCertificateOCSPAndCRL("CA Root", "CA Int", keyPair, caCert, keyPair.getPrivate(), BigInteger.ONE);
		
		System.out.println(intCert);
	}
	
}


/*
   public CRLDistributionPoints(byte[] cdps) {
    super();
    ASN1OctetString string = (ASN1OctetString)DERUtil.getDERObject(cdps);
    CRLDistPoint dp = new CRLDistPoint((ASN1Sequence)DERUtil.getDERObject(string.getOctets()));
    DistributionPoint[] cdp = dp.getDistributionPoints();
    if (cdp != null) {
      for (int i = 0; i < cdp.length; i++) {
        DistributionPointName dpn = cdp[i].getDistributionPoint();
        ASN1TaggedObject ato = (ASN1TaggedObject)dpn.toASN1Object();
        if (ato.getTagNo() == 0) {
          GeneralNames gn = GeneralNames.getInstance((ASN1TaggedObject)ato.getDERObject(), false);
          GeneralName[] names = gn.getNames();
          if (names != null) {
            for (int j = 0; j < names.length; j++) {
              if (names[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                getExtension().setProperty("cdp_" + String.valueOf(j), ((DERIA5String)names[j].getName()).getString());
              }
            }
          }
        }
      }
    }
  }
 */
