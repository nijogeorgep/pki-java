package CryptoAPI;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import Ldap.ldaputils;
import Utils.Config;

public class PathChecking {
	
    public static boolean checkPathUserCertificate(X509Certificate userCert,boolean checkCRL,PKIXCertPathChecker checker, KeyStore ks) throws Exception {
    /*
     * checkCRL: true | checker:null   -> Mode vérification original ou les crl sont vérifiée ici et doivent être signé pour l'autorité concernée et non par le certficat spécial
     * checkCRL: false | checker:null  -> Mode le plus simple ou seul le path est vérifiée (en théorie)
     * checkCRL: false | checker(PathCheckerSimple) -> vérifie CRL directement
     * checkCRL: false | checker(PathCheckerOCSP) -> fait une requete OCSP pour avoir le status du cert
     */
    	Security.addProvider(new BouncyCastleProvider());
		
    	//--- Classic stuff to retrieve Certificates
		//KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		//ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());

		X509Certificate rootCert = (X509Certificate) ks.getCertificate(Config.get("KS_ALIAS_CERT_CA","CA_Certificate"));
		X509Certificate interCert = (X509Certificate) ks.getCertificate(Config.get("KS_ALIAS_CERT_CA_INTP","CA_IntermediairePeople_Certificate"));
		//-------------
		
		X509CRL rootCRL = null;
		X509CRL interCRL = null;
		if (checkCRL) {
			JcaX509CRLConverter crlConverter = new JcaX509CRLConverter().setProvider("BC");
        	rootCRL = crlConverter.getCRL(ldaputils.getCRL("dc=pkirepository,dc=org", "rootCA"));
        	interCRL = crlConverter.getCRL(ldaputils.getCRL("ou=rootCA,dc=pkirepository,dc=org", "intermediatePeopleCA"));
		}
        
        // create CertStore to support validation
        List list = new ArrayList();
        
        list.add(rootCert);
        list.add(interCert);
        list.add(userCert);
        
        if (checkCRL) {
	    	list.add(rootCRL); //to remove if do a external PathChecker
	    	list.add(interCRL); // idem
        }
        
        CollectionCertStoreParameters params = new CollectionCertStoreParameters( list );
        CertStore  store = CertStore.getInstance("Collection", params, "BC");

        // create certificate path
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
        List               certChain = new ArrayList();

        certChain.add(userCert);
        certChain.add(interCert);
        //certChain.add(rootCert);

        CertPath certPath = fact.generateCertPath(certChain);
        
        Set      trust = Collections.singleton(new TrustAnchor(rootCert, null));

        // perform validation
        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters    param = new PKIXParameters(trust);//peut utiliser keystore
        
        if (checkCRL)
        	param.setRevocationEnabled(true); //by default
        else
        	param.setRevocationEnabled(false);
        
        if (checker != null) {
        	param.addCertPathChecker(checker);//new PathChecker(rootCert, BigInteger.ONE));
        }
        //param.setRevocationEnabled(false);//tell the CertPathValidator implementation not to expect to use CRLs, as some other revocation mechanism has been enabled
        
        param.addCertStore(store);
        param.setDate(new Date());
        
        try {
            CertPathValidatorResult result = validator.validate(certPath, param);//verifie que les crls ne sont pas perimées, que le certificat qui a signé est autorisé a signé .
            System.out.println("certificate path validated");
            return true;
        }
        catch (CertPathValidatorException e) {
            System.out.println("validation failed on certificate number " + e.getIndex() + ", details: " + e.getMessage());
            return false;
        }
    }
    
    public static void main(String[] args) throws Exception {
    	KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());

		X509Certificate userCert = (X509Certificate) ks.getCertificate("personne1_certificat");
		X509Certificate caSign = (X509Certificate) ks.getCertificate("personne1_certificat");
		
		checkPathUserCertificate(userCert, false, new PathCheckerSimple(), ks);
    }
    
}
