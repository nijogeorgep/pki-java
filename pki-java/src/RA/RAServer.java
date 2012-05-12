package RA;
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
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import Ldap.ldaputils;
import Utils.Config;
import Utils.PasswordUtils;

public class RAServer {

	ServerSocketChannel s;
	ByteBuffer masterBuffer;
	Selector sel;
	SelectionKey keyserver;
	X509Certificate caSignerCert;
	PrivateKey caSignerKey;
	KeyStore ks;
	String ldappasswd;

    public static void main(String[] args) {
        try {
    		String pass = PasswordUtils.readInPassword("LDAP: ");
    		if (!(ldaputils.isPasswordValid(pass))) {
    			System.out.println("Wrong password");
    			System.exit(1);
    		}
    		else
    			System.out.println("Password OK\nListen...");
            RAServer s = new RAServer(pass);
            s.run();
        } catch (IOException e) {
            System.out.println("Bug !\n" +e);
        } catch (InterruptedException e) {
            System.err.println("Interrupted !");
        } 
    }
    
	public RAServer(String pass) throws IOException, InterruptedException {
		this.ldappasswd = pass;
		this.s = ServerSocketChannel.open();
		this.s.socket().bind(new InetSocketAddress( new Integer(Config.get("PORT_RA", "5555"))) );
		this.s.configureBlocking(false);
		this.masterBuffer = ByteBuffer.allocate(4096);
		
		this.sel = Selector.open();
		this.keyserver= s.register(this.sel, SelectionKey.OP_ACCEPT);	//register the server selectionkey in accept

		try {
			this.ks = KeyStore.getInstance(KeyStore.getDefaultType()); //Load all the necessary certificate once
		      String path = Config.get("KS_PATH_RA","test_keystore.ks");
		      String passwd = Config.get("KS_PASS_RA","passwd");
		      this.ks.load(new FileInputStream(path), passwd.toCharArray());
			this.caSignerCert = (X509Certificate) ks.getCertificate(Config.get("KS_ALIAS_CERT_CA_SIG","CA_SigningOnly_Certificate"));
			this.caSignerKey = (PrivateKey) ks.getKey(Config.get("KS_ALIAS_KEY_CA_SIG", "CA_SigningOnly_Private"), Config.get("PASSWORD_CA_SIG","").toCharArray());
		} catch (Exception e) { e.printStackTrace();}
	}
	
	//main method in wich the main thread will be jailed.
	public void run() throws IOException, InterruptedException
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
						client.configureBlocking(false);										//configure client in non-blocking
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
                        		byte[] received = readBuff(byteread); // Read the byte[]
                            	if(sk.attachment() == null) { //If the client does not have an attachment it means this is the first message
                            		try {
                            			PKCS10CertificationRequest request = new PKCS10CertificationRequest(received); // Try to parse it as CSR Request
                            			CSRHandlerThread cli = new CSRHandlerThread(request,this.ldappasswd);
                            			cli.start();
                            			sk.attach(cli);
                            			System.out.println(request.getEncoded());
                            		}
                            		catch(Exception e) {//CSR Parsing failed, so this is a String containing the identity for a revocation
                            			String uid = new String(received); //Recreate the String from the byte[]
                            			RevocationRequestThread cli = new RevocationRequestThread(uid, this.ldappasswd, this.caSignerCert, this.caSignerKey); //Create autonomous thread
                            			cli.start(); // Start it
                            			sk.attach(cli); //Attach the class to the client
                            		}
                            	}
                            	else { // Attachment not null so we forward data received to the thread without touching it.
                            		CommunicationHandler ch = (CommunicationHandler) sk.attachment();
                            		ch.setRead(received);
                            	}
                            	sk.interestOps(SelectionKey.OP_WRITE);
                            	
                            }						
                        } 
                        catch (IOException e) {
                            System.err.println("Client closed unexpectedly!");
                            client.close();
                            continue;
                        }
					}
					
					if (sk.isWritable()) {
						
						SocketChannel client =  (SocketChannel) sk.channel(); 
						CommunicationHandler ch = (CommunicationHandler)sk.attachment(); // cast attachment as CommunicationHandler which is the Mother Class
						if (ch.getBytesToWrite() == null) {
							//Nothing to do
						}
						else {
							client.write(ByteBuffer.wrap(ch.getBytesToWrite())); //Write bytes to write without touching it.
							ch.resetBytesToWrite();
							sk.interestOps(SelectionKey.OP_READ);
						}
						
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