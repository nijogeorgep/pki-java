package Clients;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import CryptoAPI.CSRManager;
import CryptoAPI.CertificateUtils;
import Ldap.ldaputils;

public class Client_test
{
  public static void main(String[] args) throws IOException, KeyStoreException,
      NoSuchAlgorithmException, CertificateException, ClassNotFoundException
  {
    /*
    String chercherAlias = Utils.Config.get("ALIAS", "defaultval");
    
    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
    try
    {
      ks.load(new FileInputStream("src/Clients/mykeystore.ks"), "pierre"
          .toCharArray());
    }
    catch (FileNotFoundException e)
    {
      System.out.println("First launch !");
      ks.load(null);
    }
      //  X509Certificate  cert = (X509Certificate)ks.getCertificate(chercherAlias);
  //  System.out.println("Serial:"+cert.getSerialNumber());
 //   stream.writeObject(cert.getSerialNumber()); 
    */
    
    /*
    FileOutputStream fos = new FileOutputStream("t.tmp");
    ObjectOutputStream oos = new ObjectOutputStream(fos);

    oos.writeInt(12345);
    oos.writeObject("Today");

    oos.close();
    */
    //Socket socket = new Socket("localhost",6666);
    //OutputStream out = socket.getOutputStream();
    //out.write("ocucou".getBytes());
    /*
    Socket socket = new Socket("localhost", 7000);
  
    ObjectOutputStream stream = new ObjectOutputStream(socket.getOutputStream());
    stream.writeObject("coucou".getBytes());
    
    socket.close();
    */
    Security.addProvider(new BouncyCastleProvider());
    System.out.println("Nom du certificat : ");
    String nomCertif = "BOB David";
    KeyPair kp;
    PKCS10CertificationRequest csr ;
    try
    {
      kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
      try
      {
        csr =  CSRManager.generate_csr(nomCertif,kp);
        
        Socket s = new Socket("localhost", 5555); //on se connecte
        DataOutputStream out = new DataOutputStream(s.getOutputStream()); //A noter que j'utilise des DataOutputStream et pas des ObjectOutputStream
        DataInputStream in = new DataInputStream(s.getInputStream());
       
        out.write(csr.getEncoded());
        System.out.println("csr envoy�");
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
        X509Certificate cert = CertificateUtils.certificateFromByteArray(res_fitted);
        System.out.println(cert.toString());
        s.close();
        
      }
      catch (NoSuchAlgorithmException e)
      {
        e.printStackTrace();
      }
      catch (OperatorCreationException e)
      {
        e.printStackTrace();
      }
    }
    catch (NoSuchAlgorithmException e1)
    {
      e1.printStackTrace();
    } ;
//*/
  }
}
