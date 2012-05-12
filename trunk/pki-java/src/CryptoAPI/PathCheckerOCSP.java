package CryptoAPI;

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Set;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;


public class PathCheckerOCSP  extends PKIXCertPathChecker {
    private X509Certificate caCert;
    
    public PathCheckerOCSP(X509Certificate caCert)  {
        this.caCert = caCert;
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
    	
        X509Certificate x509Cert = (X509Certificate)cert; // This is the certificate we want to check
        BigInteger serial = x509Cert.getSerialNumber(); // Get the serial
        String mess = "";
        try {
			OCSPReq ocspreq = OCSPManager.generateOCSPRequest(caCert, serial); // Create an OCSP Request
			String ocspresponder = CertificateUtils.ocspURLFromCert((X509Certificate) cert); // Get the address of the OCSP Responder of the cert
			int port = new Integer(ocspresponder.split(":")[1]);
			String ip = ocspresponder.split(":")[0];
			Socket s = new Socket(ip, port); // Connect to the responder
			InputStream in = s.getInputStream();
			OutputStream out = s.getOutputStream();
			
			out.write(ocspreq.getEncoded()); // Send the OCSP Request
			
			byte[] resp = read(in); // Read the reponse
			
			s.close();
			try {
				OCSPResp response = new OCSPResp(resp); // Parse it to OCSPResp
				mess = OCSPManager.analyseResponse(response, ocspreq, caCert); // Analyse the response
			}
			catch(Exception e) {
				throw new CertPathValidatorException(new String(resp));
			}
			
		} catch (Exception e) {
			e.printStackTrace();
		}
			
		if (mess.endsWith("good"))
			System.out.println("Certificate: "+ serial + " is valid !");
		else
			throw new CertPathValidatorException(mess);
    }
    
	public byte[] read(InputStream in) {
		try {
			byte[] res = new byte[4096];
			int read = in.read(res);
			if (read == -1) {
					System.out.println("error !!");
			}
			
			byte[] res_fitted = new byte[read];
			for (int i=0; i < read; i++) {
				res_fitted[i] = res[i];
			}
			return res_fitted;
		}
		catch(Exception e) {
			return null;
		}
	}
}