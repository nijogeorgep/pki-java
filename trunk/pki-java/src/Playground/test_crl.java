package Playground;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.util.CRLFOutputStream;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

public class test_crl {
	public static X509CRLHolder createCRL(X509Certificate pub, PrivateKey priv, BigInteger serial_to_revoke) throws CertificateParsingException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, CertificateEncodingException, CertIOException, NoSuchAlgorithmException, OperatorCreationException, FileNotFoundException {
		Date now = new Date();
		//X509v2CRLBuilder crlGen = new X509v2CRLBuilder(new X500Name(pub.getIssuerDN().getName()), now);
		X509v2CRLBuilder crlGen = new X509v2CRLBuilder(new X500Name(pub.getSubjectDN().getName()), now);
		
		Date nextUpdate = new Date(now.getTime()+100000);
		X509Certificate caCrlCert = pub;
		PrivateKey caCrlPrivateKey = priv;
		
		crlGen.setNextUpdate(nextUpdate);
		
		crlGen.addCRLEntry(serial_to_revoke, now, CRLReason.privilegeWithdrawn);
		
		crlGen.addExtension(X509Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCrlCert));
		crlGen.addExtension(X509Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));//c'est moi qui ai mis 1 je pense que c'est si on en fait plusieurs
		
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(caCrlPrivateKey);//our own key
		X509CRLHolder crlholder = crlGen.build(contentSigner);
		
		return crlholder;
		//System.out.println(ASN1Dump.dumpAsString(crlholder.toASN1Structure()));
	}

	public static X509CRLHolder updateCRL(X509CRLHolder crl, PrivateKey priv, BigInteger serial) throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, CertificateParsingException, CRLException, OperatorCreationException {
		//X509V2CRLGenerator crlGen = new X509V2CRLGenerator();
		Date now = new Date();
		X509v2CRLBuilder crlGen = new X509v2CRLBuilder(crl.getIssuer(), now); //bizarre parce qu'on remet toujours date a 0 entre guillemets
		Date nextUpdate = new Date(now.getTime()+100000);
	
		crlGen.addCRL(crl);

		crlGen.addCRLEntry(serial, now, CRLReason.privilegeWithdrawn);
		
		crlGen.setNextUpdate(nextUpdate);
		
		/**
		crlGen.addExtension(X509Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCrlCert));
		crlGen.addExtension(X509Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));//c'est moi qui ai mis 1 je pense que c'est si on en fait plusieurs
		*/
		
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(priv);//our own key
		X509CRLHolder crlholder = crlGen.build(contentSigner);
		
		return crlholder;
	}
	
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, OperatorCreationException, CertException {
		Security.addProvider(new BouncyCastleProvider());
		
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());
		
		PrivateKey privca = (PrivateKey) ks.getKey("CA_Private", "monpassCA".toCharArray());
		X509Certificate pubca = (X509Certificate) ks.getCertificate("CA_Certificate");
		
		
		X509CRLHolder crl  = createCRL(pubca, privca,BigInteger.ONE);
		
		FileOutputStream out = new FileOutputStream("src/Playground/test.crl");
		out.write(crl.getEncoded());
		out.close();

		// verify the CRL
		System.out.println(crl.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(pubca)));
		
		
		// check if the CRL revokes certificate number 2
		BigInteger serial = BigInteger.ONE; 
		X509CRLEntryHolder entry = crl.getRevokedCertificate(serial);
		if (entry == null)
			System.out.println("Serial " + serial + " is not revoked");
		else {
			System.out.println("Revocation Details:");
			System.out.println("Certificate number: " + entry.getSerialNumber());
			System.out.println("Issuer            : " +crl.getIssuer());
			if (entry.hasExtensions()) {
				Extension ext = entry.getExtension(X509Extension.reasonCode);
				if (ext != null) {
					DEREnumerated     reasonCode = (DEREnumerated)X509ExtensionUtil.fromExtensionValue(ext.getExtnValue().getEncoded());
					System.out.println("Reason Code      : "+reasonCode.getValue());
		        }
			}		        
		}

	      /*
	      // place the CRL into a CertStore
	      CollectionCertStoreParameters params = new CollectionCertStoreParameters(Collections.singleton(crl));
	      CertStore                     store = CertStore.getInstance("Collection", params, "BC");
	      X509CRLSelector               selector = new X509CRLSelector();

	      selector.addIssuerName(caCert.getSubjectX500Principal().getEncoded());

	      Iterator it = store.getCRLs(selector).iterator();

	      while (it.hasNext()) {
	         crl = (X509CRL)it.next();
			*/
		
		FileInputStream in = new FileInputStream("src/Playground/test.crl");
		X509CRLHolder crlnew = new X509CRLHolder(in);
		try {
			crlnew = updateCRL(crlnew, privca, BigInteger.ZERO);
			System.out.println(ASN1Dump.dumpAsString(crl.toASN1Structure()));
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}
	
}
