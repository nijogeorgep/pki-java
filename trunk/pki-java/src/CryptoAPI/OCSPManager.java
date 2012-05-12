package CryptoAPI;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
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
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;


public class OCSPManager {
	public static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws OCSPException, OCSPException, CertificateEncodingException, OperatorCreationException, org.bouncycastle.cert.ocsp.OCSPException, IOException  {
		/*
		 * Generate an OCSP Request for the given serial.
		 */
		
        // Generate the id for the certificate we are looking for
        CertificateID id = new CertificateID(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1), new X509CertificateHolder(issuerCert.getEncoded()), serialNumber);
        
        // basic request generation with nonce
        OCSPReqBuilder ocspGen = new OCSPReqBuilder();
        
        ocspGen.addRequest(id); //Add the serial to the request (could have made the possiblity to add multiples ones)
        
        //create a nonce to avoid replay attack
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());

        Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, new DEROctetString(nonce.toByteArray()));
        ocspGen.setRequestExtensions(new Extensions(new Extension[] { ext }));
        
        return ocspGen.build();//Notate thats the request is not signed
	}

	public static void listRequest(OCSPReq req) {
		/*
		 * List all the serials requested in an OCSPReq
		 */
        Req[] requests = req.getRequestList();

        for (int i = 0; i != requests.length; i++) {
             CertificateID certID = requests[i].getCertID();

             System.out.println("OCSP Request to check certificate number " + certID.getSerialNumber());
        }
	}

	   public static OCSPResp generateOCSPResponse(OCSPReq request, X509Certificate caCert, PrivateKey privKey, X509CRLHolder crl) {
		      
		   		int response = OCSPRespBuilder.INTERNAL_ERROR; // by default response as ERROR
		   
		      SubjectPublicKeyInfo keyinfo = SubjectPublicKeyInfo.getInstance(caCert.getPublicKey().getEncoded());
		      BasicOCSPRespBuilder respGen;
		      try {
		    	  respGen = new BasicOCSPRespBuilder(keyinfo, new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1)); //Create builder
		      }catch(Exception e) { return null; }
		    	  
		     Extension ext = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
		     if (ext != null) {
		    	 respGen.setResponseExtensions(new Extensions(new Extension[] { ext })); // Put the nonce back in the response
		     }	      
		     Req[] requests = request.getRequestList();
	
		      for (int i = 0; i != requests.length; i++) { //For all the Req in the Request
		    	  	
		           CertificateID certID = requests[i].getCertID();
		           BigInteger serial = certID.getSerialNumber();
		           
		           if (CRLManager.serialNotInCRL(crl, serial)) { // If the certificate is not in the CRL
		        	   respGen.addResponse(certID, CertificateStatus.GOOD); // Set the status to good
		           }
		           else
		        	   respGen.addResponse(certID,  new RevokedStatus(new Date(), CRLReason.privilegeWithdrawn)); //Set status privilegeWithdrawn for the given ID
		      }
		      			      
			  try { 
				  ContentSigner contentSigner =  new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey);
				  BasicOCSPResp basicResp = respGen.build(contentSigner, new X509CertificateHolder[] { new X509CertificateHolder(caCert.getEncoded()) }, new Date());
				  response = OCSPRespBuilder.SUCCESSFUL; //Set response as successfull
				  return new OCSPRespBuilder().build(response, basicResp); // build the reponse
			  }catch (Exception e) {
				  return null;
			  }
	} 
	
	   
	   
	   public static String analyseResponse(OCSPResp response, OCSPReq request, X509Certificate caCert) throws Exception {
		   /*
		    * Analyse the response send regarding the request the certificate that signed the response etc ..
		    */
		   BasicOCSPResp basicResponse = (BasicOCSPResp)response.getResponseObject(); // retrieve the Basic Resp of the Response

		   // verify the response
		   if (basicResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(caCert.getPublicKey()))) {
		       SingleResp[] responses = basicResponse.getResponses();

		       byte[] reqNonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnId().getEncoded();
		       byte[] respNonce = basicResponse.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnId().getEncoded();
		       
		       // validate the nonce if it is present
		       if (reqNonce == null || Arrays.equals(reqNonce, respNonce))  { //If both nonce are equals
		    	   
		           String message = "";
		           for (int i = 0; i != responses.length;) {
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
		    return "response failed to verify OCSP signature";
	} 
	   
}
