package CryptoAPI;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
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

public class CSRManager {
	
	public static PKCS10CertificationRequest generate_csr(String name, KeyPair kp) throws NoSuchAlgorithmException, OperatorCreationException  {
		Security.addProvider(new BouncyCastleProvider());
        KeyPair keys = kp;
        
        X500Name subjectName = new X500Name("cn="+name);
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());
        PKCS10CertificationRequestBuilder csrgen = new PKCS10CertificationRequestBuilder(subjectName, keyInfo);
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keys.getPrivate());//Un peu étrange qu'on utilise notre clé privée
        return csrgen.build(contentSigner);
	}
	
	
	
	public static X509Certificate retrieveCertificateFromCSR(PKCS10CertificationRequest inputCSR, PrivateKey caPrivate, X509Certificate caPublic, BigInteger serial) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, OperatorCreationException, CertificateException {   
		Security.addProvider(new BouncyCastleProvider());
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
	    AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder() .find("SHA1withRSA");
	    AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

	    AsymmetricKeyParameter parameterCa = PrivateKeyFactory.createKey(caPrivate.getEncoded());
	    SubjectPublicKeyInfo keyInfo = inputCSR.getSubjectPublicKeyInfo();

		Calendar cal = Calendar.getInstance();
		Date	notbefore = cal.getTime();
		cal.add(Calendar.YEAR, 10);
		Date notafter = cal.getTime();
	    
	    X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(new X500Name(caPublic.getSubjectDN().getName()), serial, notbefore, notafter, inputCSR.getSubject(),	keyInfo);
	    
	    ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(parameterCa);        
	    
	    
		//------------------------- Extensions ------------------------
	    myCertificateGenerator.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(false)); //doit aussi être critique
		
	    myCertificateGenerator.addExtension(X509Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublic));
		
		SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyInfo);
		myCertificateGenerator.addExtension(X509Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
		
		// Pour le moment on autorise au CA que la signature de certificat et la signature de CRL (a priori il ne fera rien d'autre)
		KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation |KeyUsage.keyEncipherment|KeyUsage.dataEncipherment|KeyUsage.digitalSignature);
		myCertificateGenerator.addExtension(X509Extension.keyUsage, true, keyUsage); //KeyUsage doit être critique
		
		String url = "http://87.98.166.65:389/ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org";
		GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(url));
		GeneralNames gns = new GeneralNames(gn);
		DistributionPointName dpn = new DistributionPointName(gns);
		DistributionPoint distp = new DistributionPoint(dpn, null, null);
		DERSequence seq = new DERSequence(distp);
		myCertificateGenerator.addExtension(X509Extension.cRLDistributionPoints, false, seq);
        //builder.addExtension(X509Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] { point }));
		
		url = "http://87.98.166.65:80";
		gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(url));
		AuthorityInformationAccess acc = new AuthorityInformationAccess(X509Extension.authorityInfoAccess, gn);
		myCertificateGenerator.addExtension(X509Extension.authorityInfoAccess, false, acc);
		//----------------------------------------------------------------

	    
	    //myCertificateGenerator.addExtension(X509Extension.subjectKeyIdentifier, false, inputCSR.getSubjectPublicKeyInfo());
	    	    
	    
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
	
}
