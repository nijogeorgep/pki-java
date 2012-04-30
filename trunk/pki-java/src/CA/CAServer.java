package CA;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.sun.jndi.ldap.LdapClient;

import CryptoAPI.CSRManager;
import CryptoAPI.OCSPManager;
import Ldap.LDAP;
import Ldap.ldaputils;
import Utils.Config;

public class CAServer {

  ServerSocketChannel s;      //server socket
  ByteBuffer masterBuffer;    //buffer used to store temporarily bytes read in sockets
  Selector sel;
  SelectionKey keyserver;     //SelectionKey of the server

  KeyStore ks;
  
    public static void main(String[] args) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, OperatorCreationException, CertificateException {
      Security.addProvider(new BouncyCastleProvider());
        try {
            CAServer s = new CAServer();
            s.run();
        } catch (IOException e) {
            System.out.println("Bug !\n" +e);
            e.printStackTrace();
        } catch (InterruptedException e) {
            System.err.println("Interrupted !");
        } 
    }
    
  public CAServer() throws IOException, InterruptedException {
    this.s = ServerSocketChannel.open();
    this.s.socket().bind(new InetSocketAddress(5555));    //arbitrarily set to 5555
    this.s.configureBlocking(false);
    this.masterBuffer = ByteBuffer.allocate(4096);
    this.sel = Selector.open();
    this.keyserver= s.register(this.sel, SelectionKey.OP_ACCEPT); //register the server selectionkey in accept

    try {
      this.ks = KeyStore.getInstance(KeyStore.getDefaultType()); //Je load tout les certificats en m√©moire pour les avoir directement sous la main
      this.ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());
    } catch (Exception e) { e.printStackTrace();}
    
  }
  
  //main method in wich the main thread will be jailed.
  public void run() throws IOException, InterruptedException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, OperatorCreationException, CertificateException
  {
    for(;;) {
      this.sel.select(); // wait for an event
      
      Set keys = this.sel.selectedKeys();
      Iterator i = keys.iterator();
      while( i.hasNext())
      {
        SelectionKey sk = (SelectionKey) i.next();
        i.remove();
        
        if(sk.isValid()) {  //Get in only if the key is valid, which is not always the case
        
          if(sk == this.keyserver && sk.isAcceptable()) {
            SocketChannel client = ((ServerSocketChannel)sk.channel()).accept();
            client.configureBlocking(false);                    //configure client in non-blocking
            client.register(this.sel, SelectionKey.OP_READ); //register the client in READ with the given attachment (no need to do key.attach)
        }
          
          if ( sk.isReadable()) {
            SocketChannel client =  (SocketChannel) sk.channel(); //gather the socket that triggered the read event

                        this.masterBuffer.clear(); // clear the main buffer and read the client message.
                        try {
                            int byteread = client.read(this.masterBuffer);
                            if (byteread == -1) {
                                client.close();
                                continue; // avoid an CancelledKeyexception (because if we close client the key (sk) is not valid anymore and if(sk.isWritable()) will raise exception)
                            }
                            else {
                              //if(client.socket().getInetAddress().equals(Utils.Config.get("IP_RA", "")))
                              if(true)
                              {
                                //rÈcupÈration du csr
                                PKCS10CertificationRequest csr = new PKCS10CertificationRequest( readBuff(byteread));
                                PrivateKey pk = (PrivateKey) ks.getKey("CA_IntermediairePeople_Private", Config.get("PASSWORD_CA_INTP", "default_val").toCharArray());
                                //crÈation d'un certificat signÈ
                                 BigInteger bigInt = new BigInteger(ldaputils.getUIDFromSubject(csr.getSubject().toString()));
                                 
                                 X509Certificate c = CSRManager.retrieveCertificateFromCSR(csr,pk , (X509Certificate)ks.getCertificate("CA_IntermediairePeople_Certificate"), bigInt);
                                 sk.attach(c.getEncoded());
                                 sk.interestOps(SelectionKey.OP_READ|SelectionKey.OP_WRITE);
                              }
                              else
                              {
                                System.out.println("vous n'Ítes pas autorisÈ ‡ vous connecter au CA");
                                sk.interestOps(SelectionKey.OP_READ|SelectionKey.OP_WRITE);
                              }
                            }           
                        } 
                        catch (IOException e) {
                            System.err.println("Client closed unexpectedly!");
                            client.close();
                            continue;
                        }
          }
          
          if (sk.isWritable()) {
            byte[] attachment = (byte[]) sk.attachment(); //On r√©cup√®re l'attachment
            SocketChannel client =  (SocketChannel) sk.channel(); 
            client.write(ByteBuffer.wrap(attachment)); //On √©crit ce que l'on a r√©cup√©r√©
            
            sk.interestOps(SelectionKey.OP_READ); //On repasse la cl√© en read
          }
        }
        
      }
    }
  }
  
  private byte[] readBuff(int val) { //method to transform buffer into byte[]
        this.masterBuffer.flip();
    byte myarray[] = new byte[val];
    
    for(int i=0; this.masterBuffer.hasRemaining(); i++) {
      myarray [i]= this.masterBuffer.get();
    }
    return myarray;
  }
      
    private void writeSocket(SelectionKey k, ByteBuffer b) {
      SocketChannel client =  (SocketChannel) k.channel(); // gather the client socket
      try {
      client.write(b);                //write the message to the client
    } catch (IOException e) {
      e.printStackTrace();
    }
    }
    
}