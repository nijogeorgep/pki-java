package Playground;

import java.io.*;
import java.net.Socket;
import java.util.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;

import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class test_signature {

	public static void main(String[] args) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, InvalidAlgorithmParameterException, NoSuchProviderException, UnrecoverableKeyException, CertStoreException, CMSException, OperatorCreationException {
		Security.addProvider(new BouncyCastleProvider());
		
		File file_to_sign = new File("src/Playground/fichier_a_signer.txt");
		byte[] buffer = new byte[(int)file_to_sign.length()];
		DataInputStream in = new DataInputStream(new FileInputStream(file_to_sign));
		in.readFully(buffer);
		in.close();
		
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());  //JKS ou BC pour bouncy
		ks.load(new FileInputStream("src/Playground/mykeystore.ks"), "passwd".toCharArray());
		X509Certificate c = (X509Certificate) ks.getCertificate("key1"); //on considère le certificat en tant que certificat
		PrivateKey privateKey = (PrivateKey) ks.getKey("key1", "monpass".toCharArray());
		
		CMSTypedData content = new CMSProcessableByteArray(buffer);
		ArrayList certList = new ArrayList();
		certList.add(c);
		Store certs = new JcaCertStore(certList);
				
		CMSSignedDataGenerator signGen = new CMSSignedDataGenerator();
		
		ContentSigner sha1signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey);
		
		signGen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1signer, c));
		signGen.addCertificates(certs);
		
		CMSSignedData data = signGen.generate(content,true);
		
		
		Socket s = new Socket("localhost", 5555);
		ObjectOutputStream stream = new ObjectOutputStream(s.getOutputStream());
		stream.writeObject(data.getEncoded());
		stream.flush();
		/*
		System.out.println(data.getEncoded());
		FileOutputStream envfos = new FileOutputStream("output.pk7");
		envfos.write(data.getEncoded());
		envfos.close();
		*/
	}
}
