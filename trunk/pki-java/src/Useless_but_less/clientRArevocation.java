package Useless_but_less;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import CryptoAPI.CRLManager;
import CryptoAPI.CSRManager;
import CryptoAPI.CertificateUtils;
import CryptoAPI.MessageDigestUtils;
import CryptoAPI.OCSPManager;
import Ldap.ldaputils;

public class clientRArevocation {
	public static byte[] read(InputStream in) throws IOException {
		byte[] res = new byte[4096]; //Créer un tableau très grand. (Je m'attends a tout recevoir d'un coup j'ai pas envie de me faire chier)
		int read = in.read(res); //Je lis
		if (read == -1) { //si on a rien lu c'est que le serveur a eu un problème
				throw new IOException();
		}
		
		byte[] res_fitted = new byte[read]; //je déclare un tableau de la taille juste
		for (int i=0; i < read; i++) { //je recopie le byte dedans
			res_fitted[i] = res[i];
		}
		return res_fitted;
	}
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		System.out.println(CRLManager.CRLFromCrlHolder(ldaputils.getCRL("ou=rootCA,dc=pkirepository,dc=org","intermediatePeopleCA")));
		
		//System.exit(0);
		
		String nomprenom = "cn=BOB David";
		String uid = ldaputils.getUIDFromSubject(nomprenom);

		Socket s = new Socket("localhost", 6666); //on se connecte
		DataOutputStream out = new DataOutputStream(s.getOutputStream()); //A noter que j'utilise des DataOutputStream et pas des ObjectOutputStream
		DataInputStream in = new DataInputStream(s.getInputStream());
		
		//byte[] bytes = request.getEncoded(); //récupère le tableau de bytes de la requete
		//byte[] bytes = "coucou".getBytes();
		
		out.write(uid.getBytes()); //on envoie la requete
		
		String reply  = new String(read(in));
		System.out.println(new String(reply));
		
		out.write(MessageDigestUtils.digest("caca"));
		
		byte[] rep = read(in);
		String res  = new String(rep);
		System.out.println(res.toString());
		
		s.close();
		
		System.out.println(CRLManager.CRLFromCrlHolder(ldaputils.getCRL("ou=rootCA,dc=pkirepository,dc=org","intermediatePeopleCA")));
	}
}
