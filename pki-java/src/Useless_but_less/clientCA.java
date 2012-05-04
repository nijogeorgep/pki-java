package Useless_but_less;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import CryptoAPI.CSRManager;

public class clientCA {
	public static void main(String[] args) {
		Socket s;
		try {
			s = new Socket("localhost", 5555);
			DataOutputStream out = new DataOutputStream(s.getOutputStream()); //A noter que j'utilise des DataOutputStream et pas des ObjectOutputStream
			DataInputStream in = new DataInputStream(s.getInputStream());
			
			KeyPair		kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
			PKCS10CertificationRequest request = CSRManager.generate_csr("BOB David", kp);
			byte[] bytesrec = request.getEncoded(); //récupère le tableau de bytes de la requete
			
			out.write(bytesrec); //on envoie la requete
			/*
			byte[] reply  = read(in);
			
			System.out.println(reply);
			
			this.setBytesToWrite(reply);
			s.close();
		*/	
		} catch (UnknownHostException e) {
			//this.setBytesToWrite("Unknown host CA".getBytes());
			e.printStackTrace();
		} catch (Exception e) {
			//this.setBytesToWrite("'IOError CA connection".getBytes());
			e.printStackTrace();
		}
		
	}
}
