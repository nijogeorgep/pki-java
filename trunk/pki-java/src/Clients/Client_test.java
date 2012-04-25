package Clients;

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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

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
    Socket socket = new Socket("localhost", 6666);
    //OutputStream out = socket.getOutputStream();
    //out.write("ocucou".getBytes());
    ObjectOutputStream stream = new ObjectOutputStream(socket.getOutputStream());
    stream.writeObject("coucou".getBytes());
    
    socket.close();
  }
}
