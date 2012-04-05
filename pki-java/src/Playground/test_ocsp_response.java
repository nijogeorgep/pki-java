package Playground;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Vector;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;


public class test_ocsp_response {

	   public static OCSPResp generateOCSPResponse(OCSPReq request, PrivateKey privKey, X509Certificate caCert, BigInteger revokedSerial) throws NoSuchProviderException, OCSPException, IOException, OperatorCreationException, CertificateEncodingException  {
			      
		          CertificateID revokedID = new CertificateID(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1), new X509CertificateHolder(caCert.getEncoded()), revokedSerial);
		   		  //A changer comme manière de vérifier !
		          
		          //BasicOCSPRespGenerator basicRespGen = new BasicOCSPRespGenerator(pubKey);
			      //SubjectPublicKeyInfo keyinfo = request.getCerts()[0].getSubjectPublicKeyInfo(); //Récupère les infos de la personne qui demande
			      
			      SubjectPublicKeyInfo keyinfo = SubjectPublicKeyInfo.getInstance(caCert.getPublicKey().getEncoded());
			      
			      BasicOCSPRespBuilder respGen = new BasicOCSPRespBuilder(keyinfo, new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1));
			      //OCSPRespBuilder respGen = new OCSPRespBuilder();

			     Extension ext = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
			     if (ext != null) {
			    	 respGen.setResponseExtensions(new Extensions(new Extension[] { ext }));
			     }
			     			      
			     Req[] requests = request.getRequestList();

			      for (int i = 0; i != requests.length; i++) {
			           CertificateID certID = requests[i].getCertID();

			           // this would normally be a lot more general!
			           if (certID.equals(revokedID)) { // Ici on le compare a un seul certificat alors qu'il faudrait faire requete dans une CRL & Co
			               respGen.addResponse(certID,  new RevokedStatus(new Date(), CRLReason.privilegeWithdrawn));
			           }
			           else  {
			               respGen.addResponse(certID, CertificateStatus.GOOD);
			           }
			      }

			      
			      ContentSigner contentSigner =  new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey);
			      BasicOCSPResp basicResp = respGen.build(contentSigner, new X509CertificateHolder[] { new X509CertificateHolder(caCert.getEncoded()) }, new Date());
			      return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp);
		} 
	
	
	
	   public static String getStatusMessage(OCSPResp response, OCSPReq request, X509Certificate caCert) throws Exception {

		   	
			   BasicOCSPResp basicResponse = (BasicOCSPResp)response.getResponseObject(); // retrieve the Basic Resp of the Response

			   // verify the response
			   if (basicResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(caCert.getPublicKey()))) {
			       SingleResp[] responses = basicResponse.getResponses();

			       byte[] reqNonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnId().getEncoded();//tensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());
			       byte[] respNonce = basicResponse.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnId().getEncoded();
			       
			       // validate the nonce if it is present
			       if (reqNonce == null || Arrays.equals(reqNonce, respNonce))  {
			    	   
			           String message = "";
			           for (int i = 0; i != responses.length; i++) {
			                message += " certificate number " + responses[i].getCertID().getSerialNumber();
			                if (responses[i].getCertStatus() == CertificateStatus.GOOD) {
			                    return message + " status: good";
			                }
			                else {
			                    return message + " status: revoked";
			                }
			           }
			           return message;
			           
			       }
			       else {
			           return "response nonce failed to validate";
			       }
			   }
			    else {
			       return "response failed to verify";
			   }
		} 
	
	   	public static void main(String[] args) throws Exception {
			Security.addProvider(new BouncyCastleProvider());
			
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());
			
			PrivateKey cakey = (PrivateKey) ks.getKey("CA_Private", "monpassCA".toCharArray());
			X509Certificate caCert = (X509Certificate) ks.getCertificate("CA_Certificate");

			PrivateKey privInt = (PrivateKey) ks.getKey("CA_Intermediaire_Private", "monpassInt".toCharArray());
			X509Certificate pubInt = (X509Certificate) ks.getCertificate("CA_Intermediaire_Certificate");
			
			OCSPReq request = test_ocsp_request.generateOCSPRequest(caCert, pubInt.getSerialNumber()); // method from the other class
			
			
			OCSPResp response = generateOCSPResponse(request, cakey, caCert, pubInt.getSerialNumber()); //meme certificat donc il va dire révoqué !
			System.out.println(getStatusMessage(response, request, caCert));
			
			response = generateOCSPResponse(request, cakey, caCert, BigInteger.ONE); //serial rien a voir donc certificat OK
			System.out.println(getStatusMessage(response, request, caCert));			
				/*
				 Avant de considérer une réponse signée comme valide, les clients OCSP sont tenus de vérifier que: 
				Le certificat identifié dans la réponse correspond à celui identifié dans la requête; 
				la signature du message est valide; 
				l'identité du signataire de la réponse correspond à celle du destinataire attendu de la requête; 
				le signataire est autorisé à signer la requête; 
				la date pour laquelle le statut du certificat est considéré comme connu est suffisamment récente; 
				lorsque disponible, la date à ou avant laquelle une nouvelle information sera disponible pour le statut du certificat (nextUpdate) est ultérieure à la date courante. 
				
				
				 */
		} 
	
	
}
