package Repository;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import CryptoAPI.OCSPManager;
import Ldap.ldaputils;
import Useless_but_less.NeedhamSchroederPublicKey;
import Utils.Config;

public class RepositoryServer {

	ServerSocketChannel s;			//server socket
	ByteBuffer masterBuffer;		//buffer used to store temporarily bytes read in sockets
	Selector sel;
	SelectionKey keyserver;			//SelectionKey of the server
	//------ Ajout --------
	X509Certificate caSignerCert;
	PrivateKey caSignerKey;
	KeyStore ks;
	//----------------------
	
    public static void main(String[] args) {
    	Security.addProvider(new BouncyCastleProvider());
        try {
            RepositoryServer s = new RepositoryServer();
            s.run();
        } catch (IOException e) {
            System.out.println("Bug !\n" +e);
        } catch (InterruptedException e) {
            System.err.println("Interrupted !");
        } 
    }
    
	public RepositoryServer() throws IOException, InterruptedException {
		this.s = ServerSocketChannel.open();
		this.s.socket().bind(new InetSocketAddress((int) new Integer(Config.get("PORT_REPOSITORY", "5555"))));		//arbitrarily set to 5555
		this.s.configureBlocking(false);
		this.masterBuffer = ByteBuffer.allocate(4096);
		this.sel = Selector.open();
		this.keyserver= s.register(this.sel, SelectionKey.OP_ACCEPT);	//register the server selectionkey in accept
		//----- Added -----
		try {
			this.ks = KeyStore.getInstance(KeyStore.getDefaultType()); //Je load tout les certificats en mémoire pour les avoir directement sous la main
		      String path = Config.get("KS_PATH_REPOSITORY","test_keystore.ks");
		      String passwd = Config.get("KS_PASS_REPOSITORY","passwd");
		      this.ks.load(new FileInputStream(path), passwd.toCharArray());
			this.caSignerCert = (X509Certificate) ks.getCertificate(Config.get("KS_ALIAS_CERT_CA_SIG","CA_SigningOnly_Certificate"));
			this.caSignerKey = (PrivateKey) ks.getKey(Config.get("KS_ALIAS_KEY_CA_SIG", "CA_SigningOnly_Private"), Config.get("PASSWORD_CA_SIG","").toCharArray());
		} catch (Exception e) { e.printStackTrace();}
		//--------------------
		
	}
	
	//main method in wich the main thread will be jailed.
	public void run() throws IOException, InterruptedException
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
						client.configureBlocking(false);										//configure client in non-blocking
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
                            	byte[] received = readBuff(byteread);
                            	//try {
	                            	OCSPReq request  = new OCSPReq(received); //Je reconstruit cash la request OCSP a partir de ce que j'ai lu
	                            	
	                            	System.out.println(request.getEncoded()); //pour le debug
	                            	
	                            	OCSPResp response = OCSPManager.generateOCSPResponse(request, this.caSignerCert, this.caSignerKey); //Je génère la réponse (a noter ça aurait pu être bien de le mettre en sk.writable)
	                            	
	                            	System.out.println(response.getEncoded()); //pour le debug
	                            	
	                            	sk.attach(response.getEncoded()); //met le byte[] en attachment pour qu'il soit renvoyé quand il sera passé en write
	                            /*	}
                            	catch(Exception e) {
                            		BigInteger b = new BigInteger(received);
                            		String uid = b.toString();//new String(b.toByteArray());
                            		X509Certificate certB = ldaputils.getCertificate(uid);
                            		byte[] datatoresend = NeedhamSchroederPublicKey.cipherCertBWithPrivateKeyS(certB, this.caSignerKey);
                            		System.out.println(datatoresend);
                            		System.out.println("BigIn rec: "+b);
                            		sk.attach(datatoresend);
                            	}*/
                                sk.interestOps(SelectionKey.OP_READ|SelectionKey.OP_WRITE); //on le passe en write
                            }						
                        } 
                        catch (IOException e) {
                            System.err.println("Client closed unexpectedly!");
                            client.close();
                            continue;
                        }
					}
					
					if (sk.isWritable()) {
						byte[] attachment = (byte[]) sk.attachment(); //On récupère l'attachment
						SocketChannel client =  (SocketChannel) sk.channel(); 
						client.write(ByteBuffer.wrap(attachment)); //On écrit ce que l'on a récupéré
						
						sk.interestOps(SelectionKey.OP_READ); //On repasse la clé en read
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
			client.write(b);								//write the message to the client
		} catch (IOException e) {
			e.printStackTrace();
		}
    }
    
}