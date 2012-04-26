package Repository;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import CryptoAPI.OCSPManager;

public class clientocsp {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

		ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray()); //ouvre le keystore

		X509Certificate	 cert = (X509Certificate) ks.getCertificate("personne1_certificat"); //certificat du client dont on veut vérifier l'identitée
		X509Certificate issuerCert = (X509Certificate) ks.getCertificate("CA_IntermediairePeople_Certificate"); //certificat qui a signé le client (ont en a besoin pour la génération de csr)
		X509Certificate signerCert = (X509Certificate) ks.getCertificate("CA_SigningOnly_Certificate"); //certificat qui signe les crl/ocsp on l'utilise dans analyseOCSPResponse pour vérifier la signature de la reponse
		
		OCSPReq request = OCSPManager.generateOCSPRequest(issuerCert, cert.getSerialNumber()); //on crée la requete pour le certificat donné
		
		Socket s = new Socket("localhost", 5555); //on se connecte
		DataOutputStream out = new DataOutputStream(s.getOutputStream()); //A noter que j'utilise des DataOutputStream et pas des ObjectOutputStream
		DataInputStream in = new DataInputStream(s.getInputStream());
		
		byte[] bytes = request.getEncoded(); //récupère le tableau de bytes de la requete
		
		out.write(bytes); //on envoie la requete
		
		byte[] res = new byte[4096]; //Créer un tableau très grand. (Je m'attends a tout recevoir d'un coup j'ai pas envie de me faire chier)
		int read = in.read(res); //Je lis
		if (read == -1) { //si on a rien lu c'est que le serveur a eu un problème
				System.out.println("error !!");
				s.close();
		}
		
		byte[] res_fitted = new byte[read]; //je déclare un tableau de la taille juste
		for (int i=0; i < read; i++) { //je recopie le byte dedans
			res_fitted[i] = res[i];
		}
		s.close();
		
		OCSPResp response = new OCSPResp(res_fitted); //Je recrée la réponse à partir du byte[]
		
		System.out.println(response.getEncoded()); //juste pour le debug
		
		System.out.println(OCSPManager.analyseResponse(response, request, signerCert)); //Ensuite j'appelle la fonction qui me retourne le résultat de l'analyse de la réponse.
	}
}
