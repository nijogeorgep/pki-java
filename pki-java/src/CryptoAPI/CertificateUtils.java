package CryptoAPI;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

public class CertificateUtils {

	public static X509Certificate certificateFromByteArray(byte[] bytes) {
		try {
			return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(bytes));
		} catch (Exception e) {
			return null;
		}
	}
	
	public static String crlURLFromCert(X509Certificate cert) {
		String url;
		try {
			url = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(cert.getExtensionValue(X509Extension.cRLDistributionPoints.getId()))).getDistributionPoints()[0].getDistributionPoint().getName().toASN1Primitive().toString();
	        return url.substring(4, url.length()-1);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

}
