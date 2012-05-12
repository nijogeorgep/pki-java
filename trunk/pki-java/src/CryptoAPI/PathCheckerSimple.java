package CryptoAPI;

import java.math.BigInteger;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.cert.X509CRLHolder;

import Ldap.ldaputils;

public class PathCheckerSimple  extends PKIXCertPathChecker {
    //private X509Certificate caCert;
    
    public PathCheckerSimple()  {
        //this.caCert = caCert;
    }
    
    public void init(boolean forwardChecking) throws CertPathValidatorException {
        // Do nothing
    }

    public boolean isForwardCheckingSupported() {
        return true;//The isForwardCheckingSupported() should return true if the checker supports forward direction processing. All checkers must support reverse processing. 
    }

    public Set<String> getSupportedExtensions() {
        return null;//objects representing the OIDs of the X.509 extensions that the checker implementation can handle. If the checker does not handle any specific extensions, getSupportedExtensions() should return null. 
    }

    public void check(Certificate cert, Collection<String> extensions) throws CertPathValidatorException {
    	
        X509Certificate x509Cert = (X509Certificate)cert;
        BigInteger serial = x509Cert.getSerialNumber();

        X509CRLHolder crl = ldaputils.getCRLFromURL(CertificateUtils.crlURLFromCert(x509Cert)); // Get the CRL thank's to the address of the cRLDistributionPoint in the Certificate
        
        if (CRLManager.serialNotInCRL(crl, serial)) { // Check if the serial is not in the CRL
        	System.out.println("Certificate: "+ serial + " is valid !");
        }
        else {
        	throw new CertPathValidatorException("exception verifying certificate: " + serial);
        }

    }
}