package Playground;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Vector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;

import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;


public class test_ocsp_request {
	public static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws OCSPException, OCSPException, CertificateEncodingException, OperatorCreationException, org.bouncycastle.cert.ocsp.OCSPException, IOException  {
		
	        // Generate the id for the certificate we are looking for
	        //CertificateID id = new CertificateID(CertificateID.HASH_SHA1, issuerCert, serialNumber);
	        CertificateID id = new CertificateID(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1), new X509CertificateHolder(issuerCert.getEncoded()), serialNumber);
	        
	        // basic request generation with nonce
	        //OCSPReqGenerator gen = new OCSPReqGenerator();

	        OCSPReqBuilder ocspGen = new OCSPReqBuilder();
	        
	        ocspGen.addRequest(id);
	        
	        
	        // create details for nonce extension
	        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
	        /*
	        Vector     oids = new Vector();
	        Vector     values = new Vector();

	        oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
	        values.add(new Extension(false, new DEROctetString(nonce.toByteArray())));
	        */
	        Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, new DEROctetString(nonce.toByteArray()));
	        ocspGen.setRequestExtensions(new Extensions(new Extension[] { ext }));
	        
	        return ocspGen.build();//A noter que ici la requet n'est pas signée !
		}

	
	    public static void main(String[] args) throws Exception {
			Security.addProvider(new BouncyCastleProvider());
			
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());

			PrivateKey cakey = (PrivateKey) ks.getKey("CA_Private", "monpassCA".toCharArray());
			X509Certificate caCert = (X509Certificate) ks.getCertificate("CA_Certificate");

			PrivateKey privInt = (PrivateKey) ks.getKey("CA_Intermediaire_Private", "monpassInt".toCharArray());
			X509Certificate pubInt = (X509Certificate) ks.getCertificate("CA_Intermediaire_Certificate");
			
			PrivateKey privPers1 = (PrivateKey) ks.getKey("personne1_private", "monpassP1".toCharArray());
			X509Certificate pubPers1 = (X509Certificate) ks.getCertificate("personne1_certificat");

			
	        OCSPReq request = generateOCSPRequest(caCert, pubInt.getSerialNumber());

	        Req[] requests = request.getRequestList();

	        for (int i = 0; i != requests.length; i++) {
	             CertificateID certID = requests[i].getCertID();

	             System.out.println("OCSP Request to check certificate number " + certID.getSerialNumber());
	        }
	    }
}
