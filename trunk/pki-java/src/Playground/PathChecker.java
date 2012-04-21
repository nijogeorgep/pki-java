package Playground;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.*;

class PathChecker
    extends PKIXCertPathChecker
{
    private KeyPair         responderPair;
    private X509Certificate caCert;
    private BigInteger      revokedSerialNumber;
    
    public PathChecker(
        //KeyPair         responderPair,
        X509Certificate caCert,
        BigInteger      revokedSerialNumber)
    {
        //this.responderPair = responderPair;
        this.caCert = caCert;
        this.revokedSerialNumber = revokedSerialNumber;
    }
    
    public void init(boolean forwardChecking)
        throws CertPathValidatorException
    {
        // ignore
    }

    public boolean isForwardCheckingSupported()
    {
        return true;//The isForwardCheckingSupported() should return true if the checker supports forward direction processing. All checkers must support reverse processing. 
    }

    public Set getSupportedExtensions()
    {
        return null;//objects representing the OIDs of the X.509 extensions that the checker implementation can handle. If the checker does not handle any specific extensions, getSupportedExtensions() should return null. 
    }

    public void check(Certificate cert, Collection extensions)
        throws CertPathValidatorException
    {
        X509Certificate x509Cert = (X509Certificate)cert;
        
        try
        {
            //String message = OCSPResponderExample.getStatusMessage(responderPair, caCert, revokedSerialNumber, x509Cert);
            String message  = "coucou good";
            if (message.endsWith("good"))
            {
                System.out.println(message);
            }
            else
            {
                throw new CertPathValidatorException(message);
            }
        }
        catch (Exception e)
        {
            throw new CertPathValidatorException("exception verifying certificate: " + e, e);
        }
    }
}