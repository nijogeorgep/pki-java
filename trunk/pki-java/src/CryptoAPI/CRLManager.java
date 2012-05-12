package CryptoAPI;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;


public class CRLManager {
	public static X509CRLHolder createCRL(X509Certificate pub, PrivateKey priv) throws CertificateParsingException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, CertificateEncodingException, CertIOException, NoSuchAlgorithmException, OperatorCreationException, FileNotFoundException {
		/*
		 * Create an empty CRL signed with the private key. 
		 */
		Date now = new Date();
		X509v2CRLBuilder crlGen = new X509v2CRLBuilder(new X500Name(pub.getSubjectDN().getName()), now);
		
		Date nextUpdate = new Date(now.getTime()+30*24*60*60*1000); // Every 30 days
		PrivateKey caCrlPrivateKey = priv;
		
		crlGen.setNextUpdate(nextUpdate);
		
		crlGen.addExtension(X509Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));//Because we create it. The CRLNumber is 1
		
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(caCrlPrivateKey);//sign with our privatekey
		X509CRLHolder crlholder = crlGen.build(contentSigner);
		
		return crlholder;
	}

	public static X509CRLHolder updateCRL(X509CRLHolder crl, X509Certificate pub, PrivateKey priv, BigInteger serial, int reason) {
		/*
		 * Update the given CRL, adding into the given serial
		 */
		Security.addProvider(new BouncyCastleProvider());
		try {
			Date now = new Date();
			X509v2CRLBuilder crlGen = new X509v2CRLBuilder(crl.getIssuer(), now); // Create the builder
			Date nextUpdate = new Date(now.getTime()+30*24*60*60*1000);
			
			crlGen.addCRL(crl); // add the existing one into it
	
			crlGen.addCRLEntry(serial, now, reason); // Add the serial to revoke
			
			crlGen.setNextUpdate(nextUpdate);
			
			Extension ex = crl.getExtension(X509Extension.cRLNumber);
			BigInteger newnumber = new BigInteger(ex.getParsedValue().toString()).add(BigInteger.ONE); // Add one to the current value of the CRL
			
			crlGen.addExtension(X509Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(pub));
			crlGen.addExtension(X509Extension.cRLNumber, false, new CRLNumber(newnumber));
			
			ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(priv);
			X509CRLHolder crlholder = crlGen.build(contentSigner);
			
			return crlholder;
		}
		catch(Exception e) {
			return null;
		}
	}
	
	public static boolean isCRLValid(X509CRLHolder crl, X509Certificate caCert) {
		/*
		 * Check the CRL signature in accordance with the given certificate
		 */
		try {
			return crl.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(caCert));
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}
	
	public static boolean serialNotInCRL(X509CRLHolder crl, BigInteger serial) {
		/*
		 * Return true if the serial is not in the crl, false otherwise
		 */
		X509CRLEntryHolder entry = crl.getRevokedCertificate(serial);
		if (entry == null) {
			return true;
		}
		else {
			System.out.println("Revocation Details:");
			System.out.println("Certificate number: " + entry.getSerialNumber());
			System.out.println("Issuer            : " +crl.getIssuer());
			if (entry.hasExtensions()) {
				Extension ext = entry.getExtension(X509Extension.reasonCode);
				if (ext != null) {
					DEREnumerated reasonCode;
					try {
						reasonCode = (DEREnumerated)X509ExtensionUtil.fromExtensionValue(ext.getExtnValue().getEncoded());
						System.out.println("Reason Code      : "+reasonCode.getValue());
					} catch (IOException e) {e.printStackTrace();	}
		        }
			}
			return false;
		}
	}
	
	
	
	public static X509CRL CRLFromCrlHolder(X509CRLHolder crlh) {
		/*
		 * Convert from a X509CRLHolder to a X509CRL
		 */
		Security.addProvider(new BouncyCastleProvider());
		JcaX509CRLConverter crlConverter = new JcaX509CRLConverter().setProvider("BC");
    	try {
			return crlConverter.getCRL(crlh);
		} catch (CRLException e) {
			e.printStackTrace();
			return null;
		}
	}
	
}
