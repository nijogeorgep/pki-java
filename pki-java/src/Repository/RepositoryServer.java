package Repository;
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

public class RepositoryServer {

	ServerSocketChannel s;			//server socket
	ByteBuffer masterBuffer;		//buffer used to store temporarily bytes read in sockets
	Selector sel;
	SelectionKey keyserver;			//SelectionKey of the server
	
    public static void main(String[] args) {
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
		this.s.socket().bind(new InetSocketAddress(5555));		//arbitrarily set to 5555
		this.s.configureBlocking(false);
		this.masterBuffer = ByteBuffer.allocate(4096);
		
		this.sel = Selector.open();
		this.keyserver= s.register(this.sel, SelectionKey.OP_ACCEPT);	//register the server selectionkey in accept
		/* ############# README ###############
		 * Le fonctionnement du Repository est encore très très obscure dans ma tête.
		 * Normalement les certificats d'un PKI sont stocké dans un LDAP (et le prof aimerais surkifferais)
		 * Bref le repository doit fournir 4 services(servers) qui sont:
		 * 			- Serveur pour les requetes LDAP et le telechargement de certificats
		 * 			- Serveur pour que le RA se connecte pour l'ajout des nouveaux certificats et de nouvelles CRL
		 * 			- Serveur pour les demandent de CRL des clients qui veulent mettre à jour leurs CRL
		 * 			- Serveur OCSP pour les clients qui veulent savoir si un certificat est toujours valide	
		 * Bref le problème est-ce que l'on peut mutualiser toutes les connections sur un même port, ou alors il faut faire un serveur pour chaque ?
		 * Solution 1:
		 * 			On peut mutualiser. Dans ce cas un seul est même serveur reçoit toutes les connections les tris et fait des actions différentes en fonction de la requête.
		 * Solution 2:
		 * 			Il vaut mieux pas mutualiser. Dans ce cas il faut écrire une classe Repository qui permettras l'interaction et le controle de chacun des servers qui tournent
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
                                 *    ?????
                                 *###############################*/
                            	
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