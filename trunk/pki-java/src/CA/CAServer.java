package CA;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;



public class CAServer {

	ServerSocketChannel s;			//server socket
	ByteBuffer masterBuffer;		//buffer used to store temporarily bytes read in sockets
	Selector sel;
	SelectionKey keyserver;			//SelectionKey of the server
	
    public static void main(String[] args) {
        try {
        	
        	/*######### TODO #########
        	 * Avant d'écouter les requetes on doit :
        	 * Ouvrir le KeyStore qui contient globalement que le certificat privé de la CA (ou alors c'est le role du constructeur ?)
        	 * 
        	 *#######################*/
        	
            CAServer s = new CAServer();
            s.run();
        } catch (IOException e) {
            System.out.println("Bug !\n" +e);
        } catch (InterruptedException e) {
            System.err.println("Interrupted !");
        } 
    }
    
	public CAServer() throws IOException, InterruptedException {
		this.s = ServerSocketChannel.open();
		this.s.socket().bind(new InetSocketAddress(5555));		//arbitrarily set to 5555
		this.s.configureBlocking(false);
		this.masterBuffer = ByteBuffer.allocate(4096);
		
		this.sel = Selector.open();
		this.keyserver= s.register(this.sel, SelectionKey.OP_ACCEPT);	//register the server selectionkey in accept
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
						// ## ! It's just above to put an attachment to the key if needed ! (client.register(this.sel, SelectionKey.OP_READ,ATTACHMENT);
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
                                /* ############# TODO #############
                                 * Par convention on décide que le CA n'accepte que les connections du RA donc uns fois par connection on doit :
                                 * - Receptionner un message signé et le vérifier avec le certificat du RA (qui doit se trouver dans notre keystore).
                                 * Attention: tout ca ne doit se faire qu'un fois par connection (il est donc peut être bon de passer la selectionkey en writable
                                 * En cas d'échec on ferme la socket
                                 * Si tout est ok on receptionne la requete du RA qui peut être : signature d'une CSR, signature d'un révocation (et peut être d'autres trucs je sais pas)
                                 * L'ideal serait que le CA receptionne le truc a signer et détecte dynamiquement si c'est une CSR ou une révocation (ou autre)
                                 *###############################*/
                            	
                            	// ### L'ideal serait que une fois qu'on à récupéré la requete du RA on passe la key en writable et qu'on réponde les données a ce moment là.
                            	
                                // play with attachment etc..
                                //sk.interestOps(SelectionKey.OP_READ|SelectionKey.OP_WRITE);
                            }						
                        } 
                        catch (IOException e) {
                            System.err.println("Client closed unexpectedly!");
                            client.close();
                            continue;
                        }
					}
					
					if (sk.isWritable()) {

						
						
						// do whatever you want, play with attachment etc..
						//sk.interestOps(SelectionKey.OP_READ); //set back the client in read mode
						
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