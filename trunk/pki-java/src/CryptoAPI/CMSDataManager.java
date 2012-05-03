package CryptoAPI;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import Utils.Config;

public class CMSDataManager {
	public static CMSSignedData signMessage(X509Certificate cert, PrivateKey key, byte[] data) {
		Security.addProvider(new BouncyCastleProvider()); 
		CMSTypedData content = new CMSProcessableByteArray(data);
		ArrayList certList = new ArrayList();
		certList.add(cert);
		Store certs;
		try {
			certs = new JcaCertStore(certList);
			
			CMSSignedDataGenerator signGen = new CMSSignedDataGenerator();
			
			ContentSigner sha1signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(key);
			
			signGen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1signer, cert));
			signGen.addCertificates(certs);
			
			return signGen.generate(content,true); //content could have been the content of File zip = new File("fichier.zip"); CMSProcessableFile content = new CMSProcessableFile(zip);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static CMSSignedData signMessageSimple(X509Certificate cert, PrivateKey key, byte[] data) {
		Security.addProvider(new BouncyCastleProvider()); 
		CMSTypedData content = new CMSProcessableByteArray(data);
		try {
			CMSSignedDataGenerator signGen = new CMSSignedDataGenerator();
			
			ContentSigner sha1signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(key);
			
			signGen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1signer, cert));
			
			return signGen.generate(content,true); //content could have been the content of File zip = new File("fichier.zip"); CMSProcessableFile content = new CMSProcessableFile(zip);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static BigInteger getSerialFromSignedData(CMSSignedData data) {
		/*
		Store  certs = data.getCertificates();
		SignerInformation signer = (SignerInformation) data.getSignerInfos().getSigners().iterator().next(); 
	    X509CertificateHolder cert = (X509CertificateHolder) certs.getMatches(signer.getSID()).iterator().next();
	    return cert.getSerialNumber();
	    */
		return ((SignerInformation)data.getSignerInfos().getSigners().iterator().next()).getSID().getSerialNumber();
		//return ((X509Certificate) data.getCertificates().getMatches( ((SignerInformation) data.getSignerInfos().getSigners().iterator().next()).getSID()).iterator().next()).getSerialNumber();
	}
	
	public static Object verifySignedMessage(CMSSignedData data) {
		/*
		 * Verify the signature using the cert embeded into the signed object
		 */
		Security.addProvider(new BouncyCastleProvider()); 
		Object datareturn = null;
		Store  certs = data.getCertificates();
		
		SignerInformation signer = (SignerInformation) data.getSignerInfos().getSigners().iterator().next(); 

	    X509CertificateHolder cert = (X509CertificateHolder) certs.getMatches(signer.getSID()).iterator().next();
	    
	    try {
		    if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
		    	datareturn = data.getSignedContent().getContent();
		    }
	    }
	    catch(Exception e) { }
		return datareturn;
	}
	
	
	public static Object verifySignedMessage(CMSSignedData data, X509Certificate cert) {
		/*
		 * Verify the signature but does not use the certificate in the signed object
		 */
		Security.addProvider(new BouncyCastleProvider()); 
		Object datareturn = null;
		
		SignerInformation signer = (SignerInformation) data.getSignerInfos().getSigners().iterator().next(); 
	    try {
		    if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
		    	datareturn = data.getSignedContent().getContent();
		    }
	    }
	    catch(Exception e) { }
		return datareturn;
	}
	
	
	public static byte[] encryptMessage(byte[] data, X509Certificate cert)  {
		/*
		 * encrypt the data given with the cert
		 */
		Security.addProvider(new BouncyCastleProvider()); 
		CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
        try {
			edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider("BC"));
	        
	        ByteArrayOutputStream  bout = new ByteArrayOutputStream();
	        //FileOutputStream bOut = new FileOutputStream("resultat.encr");
	        OutputStream out = edGen.open(bout, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC) .setProvider("BC").build());//CMSAlgorithm.DES_EDE3_CBC
	        DEROutputStream dos = new DEROutputStream(out);
	        
	        out.write(data);
	        out.close();
	        return bout.toByteArray();
        }
        catch(Exception e) {
        	return null;
        }
	}
	
	
	public static byte[] decryptMessage(byte[] data,X509Certificate cert, PrivateKey key) {
		/*
		 * Decrypt the message and check the signature, that's why it require the cert of the signer
		 */
		Security.addProvider(new BouncyCastleProvider()); 
        byte[] cleardata = null;
		try {
	        // initialise parser 
	         CMSEnvelopedDataParser envDataParser = new CMSEnvelopedDataParser(data); 
	         RecipientInformationStore recipients =  envDataParser.getRecipientInfos(); 
	         Collection envCollection = recipients.getRecipients(); 
	         Iterator it = envCollection.iterator(); 
	
	         //if (it.hasNext()) { 
	        RecipientInformation recipient = (RecipientInformation) it.next();
	        byte[] envelopedData = recipient.getContent(new JceKeyTransEnvelopedRecipient(key));
	         //} 
	
	        byte[] signedBytes = envelopedData; 
	        CMSSignedData signedDataIn = new CMSSignedData(signedBytes);
	        Object res = verifySignedMessage(signedDataIn);
	        if(res != null) {
	        	cleardata = (byte[]) signedDataIn.getSignedContent().getContent(); 
	        }
		}
		catch(Exception e) {}
        return cleardata;
	}
	
	public static Object decryptMessage(byte[] data, PrivateKey key) {
		/*
		 * Just decrypt the message with the given private key
		 */
		Security.addProvider(new BouncyCastleProvider()); 
        //byte[] cleardata = null;
		try {
	        // initialise parser 
	         CMSEnvelopedDataParser envDataParser = new CMSEnvelopedDataParser(data); 

	        RecipientInformation recipient = (RecipientInformation) envDataParser.getRecipientInfos().getRecipients().iterator().next();
	        byte[] envelopedData = recipient.getContent(new JceKeyTransEnvelopedRecipient(key));
	        
	        //CMSSignedData signedDataIn = new CMSSignedData(envelopedData);
	        //cleardata = (byte[]) signedDataIn.getSignedContent().getContent(); 
	        return envelopedData;
		}
		catch(Exception e) {}
        return null;
	}
	
	public static Object getContentFromSignedData(CMSSignedData data) {
		return data.getSignedContent().getContent();
	}
	
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType()); //Je load tout les certificats en mémoire pour les avoir directement sous la main
		ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());
		X509Certificate cert = (X509Certificate) ks.getCertificate("CA_SigningOnly_Certificate");
		X509Certificate cert2 = (X509Certificate) ks.getCertificate("CA_IntermediairePeople_Certificate");
		PrivateKey cakey = (PrivateKey) ks.getKey("CA_SigningOnly_Private", Config.get("PASSWORD_CA_SIG","").toCharArray());
		
		byte[] mess = "coucuo".getBytes();
		/*
		CMSSignedData datasigned = signMessage(cert,cakey, mess);
		//System.out.println(verifySignedMessage(datasigned) != null);
		//System.out.println(new String((byte[]) verifySignedMessage(datasigned)));
		//System.out.println(verifySignedMessage(datasigned, cert2) != null);
		
		byte[] encrypted = encryptMessage(datasigned.getEncoded(), cert);
		
		System.out.println(decryptMessage(encrypted, cert, cakey) != null);
		System.out.println(new String((byte[]) decryptMessage(encrypted, cert, cakey)));
		*/
		//Ou en plus simple
		CMSSignedData d = signMessageSimple(cert, cakey, mess);
		SignerInformation siginf = (SignerInformation) d.getSignerInfos().getSigners().iterator().next();
		System.out.println();
		byte[] ec = encryptMessage(d.getEncoded(), cert);
		System.out.println(new String((byte[]) decryptMessage(ec, cakey)));
	}
}
