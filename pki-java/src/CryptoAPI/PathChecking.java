package CryptoAPI;

import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import Ldap.ldaputils;

public class PathChecking {
	
    public static boolean checkPathUserCertificate(X509Certificate userCert,boolean checkCRL,PKIXCertPathChecker checker, X509Certificate[] chain, X509Certificate rootCert) throws Exception {
    /*
     * checkCRL: true | checker:null   -> Mode vérification original ou les crl sont vérifiée ici et doivent être signé pour l'autorité concernée et non par le certficat spécial
     * checkCRL: false | checker:null  -> Mode le plus simple ou seul le path est vérifiée (en théorie)
     * checkCRL: false | checker(PathCheckerSimple) -> vérifie CRL directement
     * checkCRL: false | checker(PathCheckerOCSP) -> fait une requete OCSP pour avoir le status du cert
     */
    	Security.addProvider(new BouncyCastleProvider());
		
     
        // create CertStore to support validation
        List<Object> list = new ArrayList<Object>();
        
        list.add(rootCert);
        for(X509Certificate c: chain) {
        	list.add(c);
        }
        
        list.add(userCert);
        
        if (checkCRL) {
        	list.add(ldaputils.getCRLFromURL(CertificateUtils.crlURLFromCert(rootCert)));
        	for (X509Certificate c: chain) {
	    		list.add(ldaputils.getCRLFromURL(CertificateUtils.crlURLFromCert(c)));
	    	}

        }
        
        CollectionCertStoreParameters params = new CollectionCertStoreParameters( list );
        CertStore  store = CertStore.getInstance("Collection", params, "BC");

        // create certificate path
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
        List<Certificate>               certChain = new ArrayList<Certificate>();

        certChain.add(userCert);
        for (X509Certificate c: chain) {
        	certChain.add(c);
        }

        CertPath certPath = fact.generateCertPath(certChain);
        
        Set<TrustAnchor>   trust = Collections.singleton(new TrustAnchor(rootCert, null));

        // perform validation
        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters    param = new PKIXParameters(trust);//can also use a keystore
        
        if (checkCRL)
        	param.setRevocationEnabled(true); //by default
        else
        	param.setRevocationEnabled(false);
        
        if (checker != null) {
        	param.addCertPathChecker(checker);
        }
        
        param.addCertStore(store);
        param.setDate(new Date());
        
        try {
            validator.validate(certPath, param);//check that crl are not outdated, certificate valid well signed etc
            System.out.println("certificate path validated");
            return true;
        }
        catch (CertPathValidatorException e) {
            System.out.println("validation failed on certificate number " + e.getIndex() + ", details: " + e.getMessage());
            return false;
        }
    }

}
