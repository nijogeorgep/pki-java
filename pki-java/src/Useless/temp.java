package Useless;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Scanner;

public class temp {
	public static void main(String[] args) throws Exception {
		File f = new File("src/Playground/cert.fis");
		byte[] buffer = new byte[(int)f.length()];
		DataInputStream in = new DataInputStream(new FileInputStream(f));
		in.readFully(buffer);
		in.close();
		
		X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(buffer));
		
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		Scanner sc = new Scanner(System.in);
		String name =  sc.nextLine();
		ks.load(new FileInputStream(name), "".toCharArray());
		
		boolean found = false;
		Enumeration<String> en = ks.aliases();
		while(en.hasMoreElements()) {
			String al = en.nextElement();
			if(ks.isCertificateEntry(al)) {
				X509Certificate c = (X509Certificate) ks.getCertificate(al);
				try {
					cert.verify(c.getPublicKey());
					found = true;
				}catch (Exception e) {}
			}
		}
	}
}
