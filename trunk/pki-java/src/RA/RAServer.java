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
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import Utils.Config;

public class RAServer {

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
        try {
            RAServer s = new RAServer();
            s.run();
        } catch (IOException e) {
            System.out.println("Bug !\n" +e);
        } catch (InterruptedException e) {
            System.err.println("Interrupted !");
        } 
    }
    
	public RAServer() throws IOException, InterruptedException {
		this.s = ServerSocketChannel.open();
		this.s.socket().bind(new InetSocketAddress(6666));		//arbitrarily set to 5555
		this.s.configureBlocking(false);
		this.masterBuffer = ByteBuffer.allocate(4096);
		
		this.sel = Selector.open();
		this.keyserver= s.register(this.sel, SelectionKey.OP_ACCEPT);	//register the server selectionkey in accept
		//----- Added -----
		try {
			this.ks = KeyStore.getInstance(KeyStore.getDefaultType()); //Je load tout les certificats en mémoire pour les avoir directement sous la main
			this.ks.load(new FileInputStream("src/Playground/test_keystore.ks"), "passwd".toCharArray());
			this.caSignerCert = (X509Certificate) ks.getCertificate("CA_SigningOnly_Certificate");
			this.caSignerKey = (PrivateKey) ks.getKey("CA_SigningOnly_Private", Config.get("PASSWORD_CA_SIG","").toCharArray());
		} catch (Exception e) { e.printStackTrace();}
		//--------------------
		/* ############# TODO ###############
		 * Voici les autres choses que doit faire le constructeur
		 * - Lancer un thread autonome qui periodiquement :
		 * 								- créer une nouvelle crl a partir des certificats stockés dans le KeyStore
		 * 								- envoyer la crl sur le repository
		 * 								- [ Supprimer les certificats révoqué du keyStore qui sont maintenant sur le Repository ]
		 * 
		 *#################################*/
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
				
					if(sk == this.keyserver && sk.isAcceptable()) {  // sk == this.keyserver is optionnal because there's just the server registered in accept
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
                            	if(sk.attachment() == null) {
                            		try {
                            			PKCS10CertificationRequest request = new PKCS10CertificationRequest(received);
                            			CSRHandlerThread cli = new CSRHandlerThread(request);
                            			cli.start();
                            			sk.attach(cli);
                            			System.out.println(request.getEncoded());
                            		}
                            		catch(Exception e) {//c'est une demande de revocation
                            			//On fait la même chose qu'au dessus mais avec la classe qui gère la revocation
                            		}
                            	}
                            	else {
                            		CommunicationHandler ch = (CommunicationHandler) sk.attachment();
                            		ch.setRead(received);
                            		// On lit le tableau de byte en on l'envoie pel mel dans l'objet qu'on a caster en l'un ou l'autre.
                            		//On passe la keys en write
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
						//CSRHandlerThread cli = (CSRHandlerThread) sk.attachment(); //On essayera systematiquement de caster en CaClientThread si sa échou sa veut dire que c'est un Revocation..
						CommunicationHandler ch = (CommunicationHandler)sk.attachment();
						if (ch.getBytesToWrite() == null) {
							//System.out.println("nothing to do !");
						}
						else {
							System.out.println("Will write:"+ ch.getBytesToWrite());
							client.write(ByteBuffer.wrap(ch.getBytesToWrite())); //On écrit ce qu'il y a dans et l'on ne ce soucis pas des données
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
      
    private void writeSocket(SelectionKey k, ByteBuffer b) {
    	SocketChannel client =  (SocketChannel) k.channel(); // gather the client socket
    	try {
			client.write(b);								//write the message to the client
		} catch (IOException e) {
			e.printStackTrace();
		}
    }
    
}