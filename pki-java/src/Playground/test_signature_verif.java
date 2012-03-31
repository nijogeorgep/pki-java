package Playground;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;

import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

public class test_signature_verif {

	public static void main(String[] args) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, InvalidAlgorithmParameterException, NoSuchProviderException, UnrecoverableKeyException, CertStoreException, CMSException, OperatorCreationException, ClassNotFoundException {
		Security.addProvider(new BouncyCastleProvider());
		/*
		File f = new File("output.pk7");
		byte[] buffer = new byte[(int)f.length()];
		DataInputStream in = new DataInputStream(new FileInputStream(f));
		in.readFully(buffer);
		in.close();
		*/
		ServerSocket serv_s = new ServerSocket(5555);
		Socket ss = serv_s.accept();
		ObjectInputStream stream = new ObjectInputStream(ss.getInputStream());
		byte[] data =  (byte[]) stream.readObject();
		CMSSignedData s = new CMSSignedData(data);
		
		//CMSSignedData s = new CMSSignedData(buffer);
		Store               certs = s.getCertificates();//rtificatesAndCRLs("Collection", "BC");
		SignerInformationStore  signers = s.getSignerInfos();
		Collection              c = signers.getSigners();
		Iterator                it = c.iterator();
		
		while (it.hasNext())
		{
		    SignerInformation   signer = (SignerInformation) it.next();
		    
		    //Collection certCollection = certs.getCertificates(signer.getSID());
		    Collection          certCollection = certs.getMatches(signer.getSID());
		    Iterator        certIt = certCollection.iterator();
		    X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
		    
		    if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)))
		    {
				System.out.println("Is Signature valid : " + "YES");
				System.out.println("Digest : " + signer.getContentDigest());
				System.out.println("Enc Alg Oid : " + signer.getEncryptionAlgOID());
				System.out.println("Digest Alg Oid : " + signer.getDigestAlgOID());
				System.out.println("Signature : " + signer.getSignature());
				
				System.out.println("Signer Info: \n");
				
				ASN1Sequence seq = (ASN1Sequence) ASN1Sequence.fromByteArray(signer.toASN1Structure().getEncoded());
				System.out.println(seq.toString());
		        
		    }   
		}
	}
}
