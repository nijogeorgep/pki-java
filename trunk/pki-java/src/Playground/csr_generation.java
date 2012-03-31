package Playground;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
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

public class csr_generation {
	
	public static void generate_csr() throws NoSuchAlgorithmException, OperatorCreationException  {
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        KeyPair keys = keygen.generateKeyPair();
        
        X500Name subjectName = new X500Name("CN=Test V3 Certificate");
       // PKCS10CertificationRequest kpGen = new PKCS10CertificationRequest("SHA1withRSA",keys.getPublic(),	null,	keys.getPrivate()); 
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());
        PKCS10CertificationRequestBuilder csrgen = new PKCS10CertificationRequestBuilder(subjectName, keyInfo);
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keys.getPrivate());//Un peu étrange qu'on utilise notre clé privée
        PKCS10CertificationRequest theCSR = csrgen.build(contentSigner);
	}
	
	
	public static X509Certificate sign(PKCS10CertificationRequest inputCSR, PrivateKey caPrivate, KeyPair pair) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, OperatorCreationException, CertificateException {   

	    AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder() .find("SHA1withRSA");
	    AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

	    AsymmetricKeyParameter foo = PrivateKeyFactory.createKey(caPrivate.getEncoded());
	    SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());

	    
	    X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(new X500Name("CN=issuer"),
	    																																new BigInteger("1"),
	    																																new Date(System.currentTimeMillis()),
	    																																new Date(System.currentTimeMillis() + 30 * 365 * 24 * 60 * 60 * 1000),
	    																																inputCSR.getSubject(),
	    																																keyInfo);

	    ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(foo);        
	    //ici on peut ajouter des extensions et autres
	    
	    X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
	    
	    org.bouncycastle.asn1.x509.Certificate certificateStructure = holder.toASN1Structure(); 

	    java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509", "BC");

	    // Read Certificate
	    InputStream is1 = new ByteArrayInputStream(certificateStructure.getEncoded());
	    X509Certificate theCert = (X509Certificate) cf.generateCertificate(is1);
	    is1.close();
	    return theCert;
	}
	
	
	
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		try {
			//createCertificateV3new();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
