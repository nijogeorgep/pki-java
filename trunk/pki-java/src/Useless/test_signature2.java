package Useless;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.HexEncoder;
import org.bouncycastle.x509.X509CertStoreSelector;
import org.bouncycastle.x509.X509Store;

public class test_signature2 {

	public static CMSSignedData readPem(String file) throws IOException, CMSException {
		File f = new File(file);
		byte[] buffer = new byte[(int)f.length()];
		DataInputStream in = new DataInputStream(new FileInputStream(f));
		in.readFully(buffer);
		in.close();
		return new CMSSignedData(buffer);
	}
	
	public static void asn1Print(byte[] encoded) throws IOException {
		ASN1Sequence seq = (ASN1Sequence) ASN1Sequence.fromByteArray(encoded);
		System.out.println(seq.toString());
	}
	
	private static X509Certificate getCertificate(SignerInformation signer, Store cmsCertificates) throws IOException {
		X509Certificate cert = null;
		
		X509CertStoreSelector sel = new X509CertStoreSelector();
		sel.setIssuer(signer.getSID().getIssuer().getEncoded());
		sel.setSerialNumber(signer.getSID().getSerialNumber());
		
		Collection certificatesFound = cmsCertificates.getMatches(sel);
		System.out.println("Number of certificates :" +certificatesFound.size());
		Iterator it = certificatesFound.iterator();
		while (it.hasNext()) {
			cert  = (X509Certificate) it.next();
		}
		return cert;
	}
	
	
	public static void main(String[] args) throws IOException, CMSException, CertificateExpiredException, CertificateNotYetValidException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {
		Security.addProvider(new BouncyCastleProvider());
		CMSSignedData cms = readPem("output.pk7");
		
		SignerInformationStore signerStore = cms.getSignerInfos();
		
		Store cmsCertificates = cms.getCertificates();
		
		Collection signers = signerStore.getSigners();
		Iterator it = signers.iterator();
		
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			X509Certificate cert = getCertificate(signer, cmsCertificates);
			/*
			ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder().build(cert);
			
			JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
            digestCalculatorProviderBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();
            */
			boolean valid = signer.verify(cert,BouncyCastleProvider.PROVIDER_NAME);
			
			System.out.println("Is Signature valid : " + valid);
			System.out.println("Digest : " + signer.getContentDigest());
			System.out.println("Enc Alg Oid : " + signer.getEncryptionAlgOID());
			System.out.println("Digest Alg Oid : " + signer.getDigestAlgOID());
			System.out.println("Signature : " + signer.getSignature());
			
			System.out.println("Signer Info: \n");
			
			asn1Print(signer.toASN1Structure().getEncoded());
		}
		
	}
}
