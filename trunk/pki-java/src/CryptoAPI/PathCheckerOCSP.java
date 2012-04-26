package CryptoAPI;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.operator.OperatorCreationException;

import Ldap.ldaputils;

class PathCheckerOCSP  extends PKIXCertPathChecker {
    private X509Certificate caCert;
    
    public PathCheckerOCSP(X509Certificate caCert, BigInteger  revokedSerialNumber)  {
        this.caCert = caCert;
    }
    
    public void init(boolean forwardChecking) throws CertPathValidatorException {
        // Do nothing
    }

    public boolean isForwardCheckingSupported() {
        return true;//The isForwardCheckingSupported() should return true if the checker supports forward direction processing. All checkers must support reverse processing. 
    }

    public Set getSupportedExtensions() {
        return null;//objects representing the OIDs of the X.509 extensions that the checker implementation can handle. If the checker does not handle any specific extensions, getSupportedExtensions() should return null. 
    }

    public void check(Certificate cert, Collection extensions) throws CertPathValidatorException {
    	
        X509Certificate x509Cert = (X509Certificate)cert;
        BigInteger serial = x509Cert.getSerialNumber();
        String mess = "";
        try {
			OCSPReq ocspreq = OCSPManager.generateOCSPRequest(caCert, serial);
			
			Socket s = new Socket("localhost", 5555);
			ObjectOutputStream stream = new ObjectOutputStream(s.getOutputStream());
			stream.writeObject(ocspreq);
			stream.flush();
			
			ObjectInputStream instream = new ObjectInputStream(s.getInputStream());
			OCSPResp response = (OCSPResp) instream.readObject();
			mess = OCSPManager.analyseResponse(response, ocspreq, caCert);
		} catch (Exception e) {
			e.printStackTrace();
		}
			
		if (mess.endsWith("good"))
			System.out.println("Certificate: "+ serial + " is valid !");
		else
			throw new CertPathValidatorException("exception verifying certificate: " + serial);
    }
}