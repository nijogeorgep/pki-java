package CryptoAPI;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
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


public class CertificateManager {
	
	public static X509Certificate createSelfSignedCertificate(String subj, KeyPair kp, String crlurl, String ocspurl) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
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
		String		issuerName = subj; // Issuer same as subject
		BigInteger serialNumber = BigInteger.ONE;
		
		Calendar cal = Calendar.getInstance();
		Date	notBefore = cal.getTime();
		cal.add(Calendar.YEAR, 1);
		Date notAfter = cal.getTime();
		
		JcaX509v3CertificateBuilder builder  = null;
		
		X500Name subjectFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subject).build();
		X500Name issuerFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, issuerName).build();
		builder  = new JcaX509v3CertificateBuilder(issuerFormated, serialNumber, notBefore, notAfter, subjectFormated, keyPair.getPublic());

		//Signer will be the same ourselves
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate());//our own key
		
		
		//------------------------- Extensions ------------------------
		builder.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(1)); //Should be critics
		
		SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
		builder.addExtension(X509Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
		
		KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
		builder.addExtension(X509Extension.keyUsage, true, keyUsage); //KeyUsage must be critic
		
		ExtendedKeyUsage extendedKeyUsage  = new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage);
		builder.addExtension(X509Extension.extendedKeyUsage, false, extendedKeyUsage);
		
		if (crlurl != null)  {
			GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlurl));
			GeneralNames gns = new GeneralNames(gn);
			DistributionPointName dpn = new DistributionPointName(gns);
			DistributionPoint distp = new DistributionPoint(dpn, null, null);
			DERSequence seq = new DERSequence(distp);
			builder.addExtension(X509Extension.cRLDistributionPoints, false, seq);
		}
		if (ocspurl != null) {
			GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(ocspurl));
			AuthorityInformationAccess acc = new AuthorityInformationAccess(X509Extension.authorityInfoAccess, gn);
			builder.addExtension(X509Extension.authorityInfoAccess, false, acc);
		}
		//----------------------------------------------------------------
		
		X509CertificateHolder holder = builder.build(contentSigner);
		
		return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
	}

	
	public static X509Certificate createSignedCertificateIntermediaire(String issuer, String subj, KeyPair kp, X509Certificate caCert, PrivateKey caKey, BigInteger serial, String crlurl,String ocspurl) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
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
		BigInteger serialNumber = serial;
		Calendar cal = Calendar.getInstance();
		Date	notBefore = cal.getTime();
		cal.add(Calendar.YEAR, 1);
		Date notAfter = cal.getTime();
		
		JcaX509v3CertificateBuilder builder  = null;
		
		builder  = new JcaX509v3CertificateBuilder(caCert, serialNumber, notBefore, notAfter, new X500Principal("CN="+subject), keyPair.getPublic());

		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(caKey);
		
		//------------------------- Extensions ------------------------
		builder.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(0));
		
		builder.addExtension(X509Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCert));
		
		SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
		builder.addExtension(X509Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
		
		// Intermediate CA are just allowed to sign certificate (which is good enough)
		KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
		builder.addExtension(X509Extension.keyUsage, true, keyUsage);
		
		if (crlurl != null)  {
			GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlurl));
			GeneralNames gns = new GeneralNames(gn);
			DistributionPointName dpn = new DistributionPointName(gns);
			DistributionPoint distp = new DistributionPoint(dpn, null, null);
			DERSequence seq = new DERSequence(distp);
			builder.addExtension(X509Extension.cRLDistributionPoints, false, seq);
		}
		if (ocspurl != null) {
			GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(ocspurl));
			AuthorityInformationAccess acc = new AuthorityInformationAccess(X509Extension.authorityInfoAccess, gn);
			builder.addExtension(X509Extension.authorityInfoAccess, false, acc);
		}
		//----------------------------------------------------------------

		X509CertificateHolder holder = builder.build(contentSigner);
		
		return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
	}
	
	
	
	public static X509Certificate createSignedCertificateOCSPAndCRL(String issuer, String subj, KeyPair kp, X509Certificate caCert, PrivateKey caKey, BigInteger serial, String crlurl, String ocspurl) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
		/* 
		 * This method vary from createSignedCertificateIntermediaire by the right grant to this certificate which are: digitalSignature, CRLSign and OCSPSigning
		 * 
		 * EXTENSION:																	CRITICAL
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
		BigInteger serialNumber = serial;
		Calendar cal = Calendar.getInstance();
		Date	notBefore = cal.getTime();
		cal.add(Calendar.YEAR, 1);
		Date notAfter = cal.getTime();
		
		JcaX509v3CertificateBuilder builder  = null;
		
		builder  = new JcaX509v3CertificateBuilder(caCert, serialNumber, notBefore, notAfter, new X500Principal("CN="+subject), keyPair.getPublic());

		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(caKey);
		
		//------------------------- Extensions ------------------------
		builder.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(false));
		
		builder.addExtension(X509Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCert));
		
		SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
		builder.addExtension(X509Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
		
		KeyUsage keyUsage = new KeyUsage(KeyUsage.cRLSign | KeyUsage.digitalSignature | KeyUsage.nonRepudiation);
		builder.addExtension(X509Extension.keyUsage, true, keyUsage);
		
		ExtendedKeyUsage extendedKeyUsage  = new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning);
		builder.addExtension(X509Extension.extendedKeyUsage, false, extendedKeyUsage);
		
		if (crlurl != null)  {
			GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlurl));
			GeneralNames gns = new GeneralNames(gn);
			DistributionPointName dpn = new DistributionPointName(gns);
			DistributionPoint distp = new DistributionPoint(dpn, null, null);
			DERSequence seq = new DERSequence(distp);
			builder.addExtension(X509Extension.cRLDistributionPoints, false, seq);
		}
		if (ocspurl != null) {
			GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(ocspurl));
			AuthorityInformationAccess acc = new AuthorityInformationAccess(X509Extension.authorityInfoAccess, gn);
			builder.addExtension(X509Extension.authorityInfoAccess, false, acc);
		}
		//----------------------------------------------------------------

		X509CertificateHolder holder = builder.build(contentSigner);
		
		return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
	}
	
	
}
