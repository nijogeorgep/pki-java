package CryptoAPI;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;


public class OCSPManager {
	public static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws OCSPException, OCSPException, CertificateEncodingException, OperatorCreationException, org.bouncycastle.cert.ocsp.OCSPException, IOException  {
		
        // Generate the id for the certificate we are looking for
        CertificateID id = new CertificateID(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1), new X509CertificateHolder(issuerCert.getEncoded()), serialNumber);
        
        // basic request generation with nonce
        OCSPReqBuilder ocspGen = new OCSPReqBuilder();
        
        ocspGen.addRequest(id); //Faudrait aussi donner la possibilité d'ajouter plusieurs serials
        
        // create details for nonce extension
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());

        Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, new DEROctetString(nonce.toByteArray()));
        ocspGen.setRequestExtensions(new Extensions(new Extension[] { ext }));
        
        return ocspGen.build();//A noter que ici la requet n'est pas signée !
	}

	public static void listRequest(OCSPReq req) {
        Req[] requests = req.getRequestList();

        for (int i = 0; i != requests.length; i++) {
             CertificateID certID = requests[i].getCertID();

             System.out.println("OCSP Request to check certificate number " + certID.getSerialNumber());
        }
	}

	   public static OCSPResp generateOCSPResponse(OCSPReq request, X509Certificate caCert, PrivateKey privKey) throws NoSuchProviderException, OCSPException, IOException, OperatorCreationException, CertificateEncodingException, org.bouncycastle.cert.ocsp.OCSPException  {
		      
	          //CertificateID revokedID = new CertificateID(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1), new X509CertificateHolder(caCert.getEncoded()), revokedSerial);

		      SubjectPublicKeyInfo keyinfo = SubjectPublicKeyInfo.getInstance(caCert.getPublicKey().getEncoded());
		      BasicOCSPRespBuilder respGen = new BasicOCSPRespBuilder(keyinfo, new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1));

		     Extension ext = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
		     if (ext != null) {
		    	 respGen.setResponseExtensions(new Extensions(new Extension[] { ext }));
		     }	      
		     Req[] requests = request.getRequestList();

		      for (int i = 0; i != requests.length; i++) { // Pour toute les requêtes contenues dans la requete
		    	  	Req req = requests[i];
		    	  	
		           CertificateID certID = requests[i].getCertID();
		           BigInteger serial = certID.getSerialNumber();
		           //FAIRE UNE VRAI VERIFICATION !!!!
		           
		           boolean isOK = false;

		           if (isOK)
		        	   respGen.addResponse(certID, CertificateStatus.GOOD);
		           else
		        	   respGen.addResponse(certID,  new RevokedStatus(new Date(), CRLReason.privilegeWithdrawn));
		      }

		      ContentSigner contentSigner =  new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey);
		      BasicOCSPResp basicResp = respGen.build(contentSigner, new X509CertificateHolder[] { new X509CertificateHolder(caCert.getEncoded()) }, new Date());
		      return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp);
		      //RECUPERER TOUTE LES ERREURS POSSIBLE ET AU LIEU DE MERDER ENVOYER UN MESSAGE D'ERREUR
	} 
	
	   
	   
	   public static String analyseResponse(OCSPResp response, OCSPReq request, X509Certificate caCert) throws Exception {
		   BasicOCSPResp basicResponse = (BasicOCSPResp)response.getResponseObject(); // retrieve the Basic Resp of the Response

		   // verify the response
		   if (basicResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(caCert.getPublicKey()))) { //On vérifie la signature
		       SingleResp[] responses = basicResponse.getResponses();

		       byte[] reqNonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnId().getEncoded();//tensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());
		       byte[] respNonce = basicResponse.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnId().getEncoded();
		       
		       // validate the nonce if it is present
		       if (reqNonce == null || Arrays.equals(reqNonce, respNonce))  { //Si les deux nonces sont identiques
		    	   
		           String message = "";
		           for (int i = 0; i != responses.length; i++) {
		                message += " certificate number " + responses[i].getCertID().getSerialNumber();
		                if (responses[i].getCertStatus() == CertificateStatus.GOOD)
		                    return message + " status: good";
		                else
		                    return message + " status: revoked";
		           }
		           return message;
		       }
		       else
		           return "response nonce failed to validate";
		}
		else
		    return "response failed to verify";
	} 
	   
	   
    public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());

		PrivateKey privInt = (PrivateKey) ks.getKey("CA_Intermediaire_Private", "monpassInt".toCharArray());
		X509Certificate pubInt = (X509Certificate) ks.getCertificate("CA_Intermediaire_Certificate");
		
		PrivateKey privPers1 = (PrivateKey) ks.getKey("personne1_private", "monpassP1".toCharArray());
		X509Certificate pubPers1 = (X509Certificate) ks.getCertificate("personne1_certificat");

        OCSPReq request = generateOCSPRequest(pubInt, pubPers1.getSerialNumber());

        System.out.println(request);
        System.exit(0);
        
		OCSPResp response = generateOCSPResponse(request, pubInt, privInt); //meme certificat donc il va dire révoqué !
		System.out.println(analyseResponse(response, request, pubInt));

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
