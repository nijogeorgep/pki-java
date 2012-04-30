package Useless;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.crypto.SecretKey;

import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;


public class test_signature_chiffrement {
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, OperatorCreationException, CMSException {
		
		//############  ENCRYPTION ############ 

        // Zip Data 
        File zip = new File("fichier.zip"); 
        
        // initialise "BC" provider 
        Security.addProvider(new BouncyCastleProvider()); 
        
        // read public key of recipient 
        /*InputStream inStream = new FileInputStream("pathToYourCert"); 
        CertificateFactory cf = CertificateFactory.getInstance("X.509"); 
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream); 
        inStream.close(); 
		*/
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream("src/Playground/mykeystore.ks"), "passwd".toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate("key1");
        
        //get PrivateKey 
        /*KeyStore keystore = KeyStore.getInstance("PKCS12", "BC"); 
        keystore.load (new FileInputStream("pathToYourPrivateKey"), "myPassword".toCharArray()); 
        String keyAlias = "keyAlias"; 
        PrivateKey privateKey = (PrivateKey)keystore.getKey(keyAlias, "myPassword".toCharArray()); 
        */
        PrivateKey privateKey = (PrivateKey) ks.getKey("key1", "monpass".toCharArray());
        
        
        //Create Signed Data 
        /*CMSSignedDataGenerator signedDataGen = new CMSSignedDataGenerator(); 
        signedDataGen.addSigner(privateKey,cert, CMSSignedDataGenerator.ENCRYPTION_RSA, CMSSignedDataGenerator.DIGEST_SHA1); 
        CMSProcessableFile zipContent = new CMSProcessableFile(zip); 
        CMSSignedData signedData = signedDataGen.generate(zipContent, true, "BC"); 
        //TODO new added, maybe to be commented out 
        signedData = new CMSSignedData(zipContent, signedData.getEncoded()); 
        */
        CMSSignedDataGenerator signedDataGen = new CMSSignedDataGenerator();
        ContentSigner sha1signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey);
        signedDataGen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1signer, cert));
        CMSProcessableFile zipcontent = new CMSProcessableFile(zip);
        CMSSignedData signedData = signedDataGen.generate(zipcontent,true);
        signedData = new CMSSignedData(zipcontent, signedData.getEncoded());
        
        
        //Create enveloped data     
        /*CMSEnvelopedDataGenerator envDataGen = new CMSEnvelopedDataGenerator();
        envDataGen.addKeyTransRecipient(cert);         
        CMSProcessable sData = new CMSProcessableByteArray(signedData.getEncoded()); 
        CMSEnvelopedData enveloped = envDataGen.generate(sData, CMSEnvelopedDataGenerator.DES_EDE3_CBC, "BC");
        
        DEROutputStream dos = new DEROutputStream(new FileOutputStream(filename+".encr")); 
        dos.write(enveloped.getEncoded()); 
        dos.flush(); 
        dos.close();*/ 
        
        CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider("BC"));
        //ByteArrayOutputStream  bOut = new ByteArrayOutputStream();
        FileOutputStream bOut = new FileOutputStream("resultat.encr");
        OutputStream out = edGen.open(bOut, new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC) .setProvider("BC").build());
        DEROutputStream dos = new DEROutputStream(out);
        
        out.write(signedData.getEncoded());
        out.close();
        
        //This file is now encrypted in DER
        //###################################
        
        //############# DECRYPTION ############### 
        
        // initialise "BC" provider 
        //Security.addProvider(new BouncyCastleProvider()); 

        // read PrivateKey 
        /*KeyStore keystore = KeyStore.getInstance("PKCS12", "BC"); 
        keystore.load (new FileInputStream("pathToYourOtherPrivateKey"), "myPassword".toCharArray()); 
        String keyAlias = "keyAlias"; 
        PrivateKey privateKey = (PrivateKey)keystore.getKey(keyAlias, "myPassword".toCharArray()); */

        // read certificate 
        /*InputStream inStream = new FileInputStream("pathToYourOtherCer"); 
        CertificateFactory cf = CertificateFactory.getInstance("X.509"); 
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream); 
        inStream.close(); */

        FileInputStream fileInput = new FileInputStream("resultat.encr"); 
        
        // initialise parser 
         CMSEnvelopedDataParser envDataParser = new CMSEnvelopedDataParser(fileInput); 
         RecipientInformationStore recipients =  envDataParser.getRecipientInfos(); 
         Collection envCollection = recipients.getRecipients(); 
         Iterator it = envCollection.iterator(); 

         //if (it.hasNext()) { 
                RecipientInformation recipient = (RecipientInformation) it.next();
                
               // byte[] envelopedData = recipient.getContent(privateKey, "BC");
                byte[] envelopedData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privateKey));

         //} 

        byte[] signedBytes = envelopedData; 
        CMSSignedData signedDataIn = new CMSSignedData(signedBytes); 
        SignerInformation signer = (SignerInformation) signedDataIn.getSignerInfos().getSigners().iterator().next(); 
        byte[] data = (byte[]) signedDataIn.getSignedContent().getContent(); 

        //verify signature 
        //System.out.println(signer.verify(cert, "BC")); 
        System.out.println(signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)));
        
        FileOutputStream fos = new FileOutputStream("decrypted.zip"); 
        fos.write(data); 
        fos.flush(); 
        fos.close(); 
        
        //#########################################
	}
}
