package CA;
import java.io.FileInputStream;
import java.io.IOException;
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
import java.util.Set;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import CryptoAPI.CSRManager;
import Utils.Config;

public class CAServer {

	ServerSocketChannel s;
	ByteBuffer masterBuffer; // buffer used to store temporarily bytes read in sockets
	Selector sel;
	SelectionKey keyserver; // SelectionKey of the server
	PrivateKey cakey;
	X509Certificate caCert;
	KeyStore ks;
	String authorizedHost;
	String crlurl;
	String ocspurl;
	
    public static void main(String[] args) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, OperatorCreationException, CertificateException {
      Security.addProvider(new BouncyCastleProvider());
      Config.checkConfigFile();
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
    this.s.socket().bind(new InetSocketAddress( new Integer(Config.get("PORT_CA","6666"))  )); //Read in the configuration the port to listen on
    this.s.configureBlocking(false);
    this.masterBuffer = ByteBuffer.allocate(4096);
    this.sel = Selector.open();
    this.keyserver= s.register(this.sel, SelectionKey.OP_ACCEPT); //register the server selectionkey in accept
    this.authorizedHost = Config.get("IP_RA", "localhost"); //Read in the config file the only host that will be allowed to send messages
    try {
	      this.ks = KeyStore.getInstance(KeyStore.getDefaultType()); //Je load tout les certificats en mémoire pour les avoir directement sous la main
	      String path = Config.get("KS_PATH_CA","test_keystore.ks");
	      String pass = Config.get("KS_PASS_CA","passwd");
	      this.ks.load(new FileInputStream(path), pass.toCharArray());
	      
	      //Load his certificate and private key
	      this.cakey = (PrivateKey) ks.getKey(Config.get("KS_ALIAS_KEY_CA_INTP","CA_IntermediairePeople_Private"), Config.get("PASSWORD_CA_INTP", "default_val").toCharArray());
	      this.caCert = (X509Certificate)ks.getCertificate(Config.get("KS_ALIAS_CERT_CA_INTP","CA_IntermediairePeople_Certificate"));
    } catch (Exception e) {
    	System.out.println("Error while trying to open the keystore: "+Config.get("KS_PATH_CA","test_keystore.ks"));
    	System.out.println("Error message: "+e.getMessage());
    	System.exit(1);
    }
    String ldapip = Config.get("LDAP_IP","localhost");
    String ldapport = Config.get("LDAP_PORT","389");
    String repoip = Config.get("IP_REPOSITORY","localhost");
    String repoport = Config.get("PORT_REPOSITORY", "7003");
    this.crlurl = "ldap://" + ldapip + ":" + ldapport + "/" + Config.get("USERS_BASE_DN","");
    this.ocspurl = "http://" + repoip + ":" + repoport;
  }
  
  //main method in wich the main thread will be jailed.
  public void run() throws IOException, InterruptedException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, OperatorCreationException, CertificateException
  {
    for(;;) {
      this.sel.select(); // wait for an event
      
      Set<SelectionKey> keys = this.sel.selectedKeys();
      Iterator<SelectionKey> i = keys.iterator();
      while( i.hasNext())
      {
        SelectionKey sk = (SelectionKey) i.next();
        i.remove();
        
        if(sk.isValid()) {  //Get in only if the key is valid, which is not always the case
        
          if(sk == this.keyserver && sk.isAcceptable()) {
            SocketChannel client = ((ServerSocketChannel)sk.channel()).accept();
            client.configureBlocking(false);                    //configure client in non-blocking
            client.register(this.sel, SelectionKey.OP_READ);
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

                            String h_addr = client.socket().getInetAddress().getHostAddress();
                            String h_name = client.socket().getInetAddress().getHostName();
                            
                              if(this.authorizedHost.equals(h_name) || this.authorizedHost.equals(h_addr)) {//Process messages only if they come from the authorizedHost
	                               //Read in the CSR
                            	  	System.out.println("CSR received from: "+ client.socket().getInetAddress().toString());
	                               PKCS10CertificationRequest csr = new PKCS10CertificationRequest( readBuff(byteread));
	                               BigInteger bigInt = new BigInteger(String.valueOf(System.currentTimeMillis())); //The serial will be the timestamp, by this way we are none will be the same.
	                               X509Certificate c = CSRManager.retrieveCertificateFromCSR(csr,cakey , caCert, bigInt, crlurl, ocspurl); //Call the method with his own certificate and key.
	                               sk.attach(c.getEncoded()); //Attach back the certificate, to allow it to be written back to the RA.
	                               sk.interestOps(SelectionKey.OP_WRITE); // switch key to write
                              }
                              else
                              {
                                client.write(ByteBuffer.wrap("Not Authorized to connect\n".getBytes())); 
                                client.close(); //Kick the no authorized client
                                System.out.println("Unauthorized IP kicked !");
                                continue;
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
	            byte[] attachment = (byte[]) sk.attachment(); //Get the attachment which is a certificate encoded in byte []
	            SocketChannel client =  (SocketChannel) sk.channel(); 
	            client.write(ByteBuffer.wrap(attachment)); //Write it back
	            
	            sk.interestOps(SelectionKey.OP_READ); //Put the key back in read
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
          
}