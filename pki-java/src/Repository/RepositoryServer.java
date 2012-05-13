package Repository;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import CryptoAPI.OCSPManager;
import Ldap.ldaputils;
import Utils.Config;

public class RepositoryServer {

	ServerSocketChannel s;			//server socket
	ByteBuffer masterBuffer;		//buffer used to store temporarily bytes read in sockets
	Selector sel;
	SelectionKey keyserver;			//SelectionKey of the server
	X509Certificate caSignerCert;
	PrivateKey caSignerKey;
	KeyStore ks;
	X509CRLHolder crl;
	
    public static void main(String[] args) {
    	Security.addProvider(new BouncyCastleProvider());
    	Config.checkConfigFile();
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
		this.s.socket().bind(new InetSocketAddress((int) new Integer(Config.get("PORT_REPOSITORY", "5555"))));
		this.s.configureBlocking(false);
		this.masterBuffer = ByteBuffer.allocate(4096);
		this.sel = Selector.open();
		this.keyserver= s.register(this.sel, SelectionKey.OP_ACCEPT);
		//----- Added -----
		try {
			this.ks = KeyStore.getInstance(KeyStore.getDefaultType());
		      String path = Config.get("KS_PATH_REPOSITORY","test_keystore.ks");
		      String passwd = Config.get("KS_PASS_REPOSITORY","passwd");
		      this.ks.load(new FileInputStream(path), passwd.toCharArray());
			this.caSignerCert = (X509Certificate) ks.getCertificate(Config.get("KS_ALIAS_CERT_CA_SIG","CA_SigningOnly_Certificate"));
			this.caSignerKey = (PrivateKey) ks.getKey(Config.get("KS_ALIAS_KEY_CA_SIG", "CA_SigningOnly_Private"), Config.get("PASSWORD_CA_SIG","").toCharArray());
		} catch (Exception e) {
	    	System.out.println("Error while trying to open the keystore: "+Config.get("KS_PATH_CA","test_keystore.ks"));
	    	System.out.println("Error message: "+e.getMessage());
	    	System.exit(1);
		}
		//--------------------
		
	}
	
	public void run() throws IOException, InterruptedException
	{
		for(;;) {
			this.sel.select();
			
			Set<SelectionKey> keys = this.sel.selectedKeys();
			Iterator<SelectionKey> i = keys.iterator();
			while( i.hasNext())
			{
				SelectionKey sk = (SelectionKey) i.next();
				i.remove();
				
				if(sk.isValid()) {
				
					if(sk == this.keyserver && sk.isAcceptable()) {
						SocketChannel client = ((ServerSocketChannel)sk.channel()).accept();
						client.configureBlocking(false);
						client.register(this.sel, SelectionKey.OP_READ);
				}
					
					if ( sk.isReadable()) {
						SocketChannel client =  (SocketChannel) sk.channel(); //gather the socket that triggered the read event

                        this.masterBuffer.clear(); // clear the main buffer and read the client message.
                        try {
                            int byteread = client.read(this.masterBuffer);
                            if (byteread == -1) {
                                client.close();
                                continue;
                            }
                            else {
                            	byte[] received = readBuff(byteread);
                            	try {
                            	OCSPReq request  = new OCSPReq(received); //Recreate the OCSPReq from the byte[] read
                            	this.crl = ldaputils.getCRL("ou=rootCA,dc=pkirepository,dc=org", "intermediatePeopleCA");
                            	OCSPResp response = OCSPManager.generateOCSPResponse(request, this.caSignerCert, this.caSignerKey, crl); //Generate the response
                            	
                            	sk.attach(response.getEncoded()); //put the reponse as byte[]

                                sk.interestOps(SelectionKey.OP_READ|SelectionKey.OP_WRITE);// Put the key in write
                            	}
                            	catch(Exception e) {
                            		sk.attach("Invalid request".getBytes());
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
						byte[] attachment = (byte[]) sk.attachment();
						SocketChannel client =  (SocketChannel) sk.channel(); 
						client.write(ByteBuffer.wrap(attachment));
						
						sk.interestOps(SelectionKey.OP_READ);
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