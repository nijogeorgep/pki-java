package Playground;
 
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.*;
import java.util.*;

import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.sun.org.apache.xpath.internal.operations.And;

/**
 * Basic example of certificate path validation using a PKIXCertPathChecker
 */
public class cert_path_validation
{
    public static void main(String[] args) throws Exception {
    	Security.addProvider(new BouncyCastleProvider());
		
    	//--- Classic stuff to retrieve Certificates
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream("src/Playground/test_keystore_alt.ks"), "passwd".toCharArray());

		X509Certificate rootCert = (X509Certificate) ks.getCertificate("CA_Certificate");
		X509Certificate interCert = (X509Certificate) ks.getCertificate("CA_Intermediaire_Certificate");
		X509Certificate endCert = (X509Certificate) ks.getCertificate("personne1_certificat");
		PrivateKey cakey = (PrivateKey) ks.getKey("CA_Private", "monpassCA".toCharArray());
		PrivateKey privInt = (PrivateKey) ks.getKey("CA_Intermediaire_Private", "monpassInt".toCharArray());
		PrivateKey endKey = (PrivateKey) ks.getKey("personne1_private", "monpassP1".toCharArray());
		//-------------
        
        BigInteger      revokedSerialNumber = BigInteger.valueOf(3);
        
        // Without Checker
        JcaX509CRLConverter crlConverter = new JcaX509CRLConverter().setProvider("BC");
        X509CRL         rootCRL = crlConverter.getCRL(test_crl.createCRL(rootCert, cakey, revokedSerialNumber));//X509CRLExample.createCRL(rootCert, rootPair.getPrivate(), revokedSerialNumber);
        X509CRL         interCRL = crlConverter.getCRL(test_crl.createCRL(interCert, privInt, revokedSerialNumber));//X509CRLExample.createCRL(interCert, interPair.getPrivate(), revokedSerialNumber);
        //----------------------
        //System.out.println(interCRL);
        //System.exit(0);
        
        // create CertStore to support validation
        List list = new ArrayList();
        
        list.add(rootCert);
        list.add(interCert);
        list.add(endCert);
        //Whitout Checker
        list.add(rootCRL);
        list.add(interCRL);
        //-------------------------
        
        CollectionCertStoreParameters params = new CollectionCertStoreParameters( list );
        CertStore  store = CertStore.getInstance("Collection", params, "BC");

        // create certificate path
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
        List               certChain = new ArrayList();

        certChain.add(endCert);
        certChain.add(interCert);
        //certChain.add(rootCert);

        System.out.println(certChain.toString());
        
        CertPath certPath = fact.generateCertPath(certChain);
        
        Set      trust = Collections.singleton(new TrustAnchor(rootCert, null));

        // perform validation
        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters    param = new PKIXParameters(trust);//peut utiliser keystore
        
        // For PathChecker
        //param.addCertPathChecker(new PathChecker(rootPair, rootCert, revokedSerialNumber));
        //tell the CertPathValidator implementation not to expect to use CRLs, as some other revocation mechanism has been enabled
        //param.setRevocationEnabled(false);
        
        param.addCertStore(store);
        param.setDate(new Date());
        
        try {
            CertPathValidatorResult result = validator.validate(certPath, param);

            System.out.println("certificate path validated");
        }
        catch (CertPathValidatorException e) {
        	e.printStackTrace();
            //System.out.println("validation failed on certificate number " + e.toString() + ", details: " + e.getMessage());
        }
    }
}

