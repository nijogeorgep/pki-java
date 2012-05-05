package Playground;
 
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
//import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

//import javax.security.auth.x500.X500Principal;

/**
 * Basic example of certificate path validation
 */
public class CertPathValidatorExample
{
    public static void main(String[] args)  throws Exception {
    	Security.addProvider(new BouncyCastleProvider());
        // create certificates and CRLs
        KeyPair         rootPair = Utils.generateRSAKeyPair();
        KeyPair         interPair = Utils.generateRSAKeyPair();
        KeyPair         endPair = Utils.generateRSAKeyPair();
        

		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());

		X509Certificate rootCert = (X509Certificate) ks.getCertificate("CA_Certificate");
		X509Certificate interCert = (X509Certificate) ks.getCertificate("CA_Intermediaire_Certificate");
		X509Certificate endCert = (X509Certificate) ks.getCertificate("personne1_certificat");
		PrivateKey cakey = (PrivateKey) ks.getKey("CA_Private", "monpassCA".toCharArray());
		PrivateKey privInt = (PrivateKey) ks.getKey("CA_Intermediaire_Private", "monpassInt".toCharArray());
		PrivateKey endKey = (PrivateKey) ks.getKey("personne1_private", "monpassP1".toCharArray());
		
        /*
        X509Certificate rootCert = Utils.generateRootCert(rootPair);
        X509Certificate interCert = Utils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
        X509Certificate endCert = Utils.generateEndEntityCert(endPair.getPublic(), interPair.getPrivate(), interCert);
        */
        BigInteger      revokedSerialNumber = BigInteger.valueOf(2);
        X509CRL         rootCRL = X509CRLExample.createCRL(rootCert, cakey, revokedSerialNumber);//X509CRL         rootCRL = X509CRLExample.createCRL(rootCert, rootPair.getPrivate(), revokedSerialNumber);
        X509CRL         interCRL = X509CRLExample.createCRL(interCert, privInt, revokedSerialNumber);//X509CRL         interCRL = X509CRLExample.createCRL(interCert, interPair.getPrivate(), revokedSerialNumber);
        
        // create CertStore to support validation
        List list = new ArrayList();
        
        list.add(rootCert);
        list.add(interCert);
        list.add(endCert);
        list.add(rootCRL);
        list.add(interCRL);
        
        CollectionCertStoreParameters params = new CollectionCertStoreParameters( list );
        CertStore                     store = CertStore.getInstance("Collection", params, "BC");

        // create certificate path
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
        List               certChain = new ArrayList();

        certChain.add(endCert);
        certChain.add(interCert);

        System.out.println(certChain.toString());
        
        CertPath certPath = fact.generateCertPath(certChain);
        Set      trust = Collections.singleton(new TrustAnchor(rootCert, null));

        // perform validation
        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters    param = new PKIXParameters(trust);
        
        param.addCertStore(store);
        param.setDate(new Date());
        
//        X509CertSelector selector = new X509CertSelector();
//        
//        selector.setSubject(new X500Principal("CN=No Match"));
//        param.setTargetCertConstraints(selector);
        
        try
        {
            CertPathValidatorResult result = validator.validate(certPath, param);

            System.out.println("certificate path validated");
        }
        catch (CertPathValidatorException e)
        {
            System.out.println("validation failed on certificate number " + e.getIndex() + ", details: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

