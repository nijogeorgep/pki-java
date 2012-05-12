package CryptoAPI;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.x509.extension.X509ExtensionUtil;


public class CertificateUtils {

	public static X509Certificate certificateFromByteArray(byte[] bytes) {
		/*
		 * Return an X509Certificate from a certificate encoded in byte[]
		 */
		try {
			return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(bytes));
		} catch (Exception e) {
			return null;
		}
	}
	
	public static String crlURLFromCert(X509Certificate cert) {
		/*
		 * Return the crlDistributionPoints extension from a certificate
		 */
		String url;
		try {
			url = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(cert.getExtensionValue(X509Extension.cRLDistributionPoints.getId()))).getDistributionPoints()[0].getDistributionPoint().getName().toASN1Primitive().toString();
	        return url.substring(4, url.length()-1);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static String ocspURLFromCert(X509Certificate cert) {
		/*
		 * Return the OCSP Responder address contained in the certificate
		 * More precisely the it is contained in the authorityInfoAccess extension
		 */
		try {
			return AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(cert.getExtensionValue(X509Extension.authorityInfoAccess.getId()))).getAccessDescriptions()[0].getAccessLocation().getName().toASN1Primitive().toString().split("://")[1];
		}catch(Exception e) {
			return null;
		}
	}
	
	public static Certificate[] createNewChain(Certificate[] chain, X509Certificate cert) {
		/*
		 * Add the given certificate to the chain Certificate[]
		 */
		Certificate[] newchain = new Certificate[chain.length+1];
		for(int i=0; i < chain.length ; i ++)
			newchain[i] = chain[i];
		newchain[chain.length] = cert;
		return newchain;
	}
	
}
