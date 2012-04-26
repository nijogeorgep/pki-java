package Useless;
 
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.*;
import java.util.*;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import CryptoAPI.CRLManager;

/**
 * Basic example of certificate path validation using a PKIXCertPathChecker
 */
public class cert_path_validation
{
    public static void main(String[] args) throws Exception {
    	
    	boolean VERIFIED_BY_PATH_CHECKER = false;
    	
    	Security.addProvider(new BouncyCastleProvider());
		
    	//--- Classic stuff to retrieve Certificates
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());

		X509Certificate rootCert = (X509Certificate) ks.getCertificate("CA_Certificate");
		X509Certificate interCert = (X509Certificate) ks.getCertificate("CA_IntermediairePeople_Certificate");
		X509Certificate endCert = (X509Certificate) ks.getCertificate("personne1_certificat");
		PrivateKey cakey = (PrivateKey) ks.getKey("CA_Private", "passwordRootCA".toCharArray());
		PrivateKey privInt = (PrivateKey) ks.getKey("CA_IntermediairePeople_Private", "passwordPeopleCA".toCharArray());
		PrivateKey endKey = (PrivateKey) ks.getKey("personne1_private", "monpassP1".toCharArray());
		X509Certificate sigpub = (X509Certificate) ks.getCertificate("CA_SigningOnly_Certificate");
		PrivateKey sigpriv = (PrivateKey) ks.getKey("CA_SigningOnly_Private", "passwordSigningCert".toCharArray());
		//-------------
        
        //BigInteger      revokedSerialNumber = BigInteger.valueOf(3);
        
        // Without Checker
        JcaX509CRLConverter crlConverter = new JcaX509CRLConverter().setProvider("BC");
        X509CRL         rootCRL = crlConverter.getCRL(CRLManager.createCRL(rootCert, cakey));
        X509CRLHolder crlh = CRLManager.createCRL(interCert, privInt);
        
        crlh = CRLManager.updateCRL(crlh, interCert, privInt, BigInteger.ONE, CRLReason.privilegeWithdrawn);
        X509CRL         interCRL = crlConverter.getCRL(crlh);
        
        //----------------------
        //System.out.println(rootCRL);
        //System.exit(0);
        
        // create CertStore to support validation
        List list = new ArrayList();
        
        list.add(rootCert);
        list.add(interCert);
        list.add(endCert);
        
        //if (!(VERIFIED_BY_PATH_CHECKER)) {
        	list.add(rootCRL);
        	list.add(interCRL);
        //}
        //-------------------------
        
        CollectionCertStoreParameters params = new CollectionCertStoreParameters( list );
        CertStore  store = CertStore.getInstance("Collection", params, "BC");

        // create certificate path
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
        List               certChain = new ArrayList();

        certChain.add(endCert);
        certChain.add(interCert);
        //certChain.add(rootCert);

        //System.out.println(certChain.toString());
        
        CertPath certPath = fact.generateCertPath(certChain);
        
        Set      trust = Collections.singleton(new TrustAnchor(rootCert, null));

        // perform validation
        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters    param = new PKIXParameters(trust);//peut utiliser keystore
        //param.setRevocationEnabled(false);
        
        if (VERIFIED_BY_PATH_CHECKER) {
	        // For PathChecker
	        //param.addCertPathChecker(new PathChecker(rootCert, BigInteger.ONE));
	        //param.setRevocationEnabled(false);//tell the CertPathValidator implementation not to expect to use CRLs, as some other revocation mechanism has been enabled

        }
        
        param.addCertStore(store);
        param.setDate(new Date());
        
        try {
            CertPathValidatorResult result = validator.validate(certPath, param);//verifie que les crls ne sont pas perimées, que le certificat qui a signé est autorisé a signé ..

            System.out.println("certificate path validated");
        }
        catch (CertPathValidatorException e) {
        	//e.printStackTrace();
            System.out.println("validation failed on certificate number " + e.getIndex() + ", details: " + e.getMessage());
        }
    }
}

