package CryptoAPI;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
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
import Utils.Config;

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

    public Set getSupportedExtensions() {
        return null;//objects representing the OIDs of the X.509 extensions that the checker implementation can handle. If the checker does not handle any specific extensions, getSupportedExtensions() should return null. 
    }

    public void check(Certificate cert, Collection extensions) throws CertPathValidatorException {
    	
        X509Certificate x509Cert = (X509Certificate)cert;
        BigInteger serial = x509Cert.getSerialNumber();
        String mess = "";
        try {
			OCSPReq ocspreq = OCSPManager.generateOCSPRequest(caCert, serial);
			
			int port = (int) new Integer(Config.get("PORT_REPOSITORY", "5555"));
			String ip = Config.get("IP_REPOSITORY", "localhost");
			Socket s = new Socket(ip, port);
			InputStream in = s.getInputStream();
			OutputStream out = s.getOutputStream();
			
			out.write(ocspreq.getEncoded());
			
			byte[] resp = read(in);
			
			s.close();

			OCSPResp response = new OCSPResp(resp);
			
			mess = OCSPManager.analyseResponse(response, ocspreq, caCert);
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
			byte[] res = new byte[4096]; //Créer un tableau très grand. (Je m'attends a tout recevoir d'un coup j'ai pas envie de me faire chier)
			int read = in.read(res); //Je lis
			if (read == -1) { //si on a rien lu c'est que le serveur a eu un problème
					System.out.println("error !!");
			}
			
			byte[] res_fitted = new byte[read]; //je déclare un tableau de la taille juste
			for (int i=0; i < read; i++) { //je recopie le byte dedans
				res_fitted[i] = res[i];
			}
			return res_fitted;
		}
		catch(Exception e) {
			return null;
		}
	}
}