package CryptoAPI;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;

public class CertificateUtils {

	public static X509Certificate certificateFromByteArray(byte[] bytes) {
		try {
			return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(bytes));
		} catch (Exception e) {
			//e.printStackTrace();
			return null;
		}
	}
	

}
