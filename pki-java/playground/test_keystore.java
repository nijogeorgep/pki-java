import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;


public class test_keystore {
	
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
		
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());  //JKS ou BC pour bouncy
		
		try {
			ks.load(new FileInputStream("my_keystore.ks"), "passwd".toCharArray());
		}
		catch (FileNotFoundException e) {
			System.out.println("First launch !");
			ks.load(null);
		}
        
		//search for a specific key !
		if(ks.containsAlias("mykey"))  {
			Key k = ks.getKey("mykey", "monpass".toCharArray()); // on considère le certificat en tant que clé
			System.out.println(k.toString());
			Certificate c = ks.getCertificate("mykey"); //on considère le certificat en tant que certificat
			System.out.println(c.toString());
		}
		else {
			//il faut le créer et l'ajouter !
		}
		
		Enumeration<String> en = ks.aliases(); //On itère tout les clés du keystore et affiche l'alias
		while(en.hasMoreElements())
			System.out.println(en.nextElement());
		
		
        ks.store(new FileOutputStream("my_keystore.ks"), "passwd".toCharArray());
	}
	
}
