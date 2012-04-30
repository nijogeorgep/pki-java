package Useless;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


public class client_test {
	
	public static void main(String[] args) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		/*SocketChannel s = SocketChannel.open();
		s.connect(new InetSocketAddress("localhost",5555));
		String message = "Coucou";
		s.write(ByteBuffer.wrap(message.getBytes()));
		s.close();*/
		
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());  //JKS ou BC pour bouncy
		
		try {
			ks.load(new FileInputStream("src/Playground/mykeystore.ks"), "passwd".toCharArray());
		}
		catch (FileNotFoundException e) {
			System.out.println("First launch !");
			ks.load(null);
		}
		
        X509Certificate c = null;
		if(ks.containsAlias("key1"))  {
			c = (X509Certificate) ks.getCertificate("key1"); //on considère le certificat en tant que certificat
		}
		
		Socket s = new Socket("localhost", 5555);
		ObjectOutputStream stream = new ObjectOutputStream(s.getOutputStream());
		stream.writeObject(c);
		stream.flush();

	}
}
