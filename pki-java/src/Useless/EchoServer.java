package Useless;
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



public class EchoServer {

	ServerSocketChannel s;			//server socket
	ByteBuffer masterBuffer;		//buffer used to store temporarily bytes read in sockets
	Selector sel;
	SelectionKey keyserver;			//SelectionKey of the server
	ClockThread r;
	LinkedList<SetOfElements> list;	//List that the buffer will endlessly iterate to write contents after 2sec

    private class SetOfElements {	//Class that will be sent to the "writing thread" via the linkedlist
    	public long timestamp;		//I have put all variable in public to allow them to be accessed directly without get (to do not complexify the code)
    	public SelectionKey key;
    	public ByteBuffer buffer;
    	public SetOfElements(long timestp, SelectionKey k, ByteBuffer b) { //Constructor receive the timestamp at which the message b as been received on the SelectionKey k
    		this.timestamp = timestp;
    		this.key = k;
    		this.buffer = b;
    	}
    };
	
    public static void main(String[] args) {
        try {
            EchoServer s = new EchoServer();
            s.run();
        } catch (IOException e) {
            System.out.println("Bug !\n" +e);
        } catch (InterruptedException e) {
            System.err.println("Interrupted !");
        } 
    }
    
	public EchoServer() throws IOException, InterruptedException {
		this.s = ServerSocketChannel.open();
		this.s.socket().bind(new InetSocketAddress(5555));		//arbitrarily set to 5555
		this.s.configureBlocking(false);
		this.masterBuffer = ByteBuffer.allocate(4096);
		
		this.sel = Selector.open();
		this.keyserver= s.register(this.sel, SelectionKey.OP_ACCEPT);	//register the server selectionkey in accept
                
        this.list = new LinkedList<SetOfElements>(); // LinkedList choosed because fastest than ArrayList in add/delete operations.
        
        //Thread creation
        this.r = new ClockThread(this.list); //send him the list otherwise he would not be able to access it.
        this.r.start();
	}
	
	//main method in wich the main thread will be jailed.
	public void run() throws IOException, InterruptedException
	{
		for(;;)
		{
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
						BlockingQueue<ByteBuffer> bbq = new LinkedBlockingQueue<ByteBuffer>() ; //instantiate an empty blockingqueue that we put in attachment
						client.register(this.sel, SelectionKey.OP_READ,bbq); //register the client in READ with the given attachment (no need to do key.attach)
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
                                ((BlockingQueue<ByteBuffer>) sk.attachment()).add(ByteBuffer.wrap(this.readBuff(byteread))); //add the bytebuffer in the client BlockingQueue
                                sk.interestOps(SelectionKey.OP_READ|SelectionKey.OP_WRITE);
                                //
                            }						
                        } 
                        catch (IOException e) {
                            System.err.println("Client closed unexpectedly!");
                            client.close();
                            continue;
                        }

						
					}
					if (sk.isWritable()) {

						BlockingQueue<ByteBuffer> bq = ((BlockingQueue<ByteBuffer>) sk.attachment());

						//will flush the blocking queue of the client creating for each BytBuffer a class SetOfElement which is added in the LinkedList that the thread
						// iterate without an end.
                        while (!(bq.isEmpty())) {
                            SetOfElements elts = new SetOfElements(System.currentTimeMillis(), sk, (ByteBuffer) bq.take());
                        	this.list.add(elts); 
                        }

						sk.interestOps(SelectionKey.OP_READ); //set back the client in read mode
						
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
        
    //the thread is created into the same class as EchoServer as a private class because I had considered it as a built-in subroutine of the server    
    private class ClockThread extends Thread implements Runnable {
    	LinkedList<SetOfElements> l;
    	public ClockThread(LinkedList<SetOfElements> sentlist) { // constructor just take the LinkedList created in EchoServer
    		this.l = sentlist;
    	}
    	
        public void run()  { //method that implement Runnable
        	for (;;) {
    			try {
					Thread.sleep(10);// avoid to load CPU at 100%
    			} catch (InterruptedException e) {	break; }
    			
        		long now = System.currentTimeMillis(); // Get the timestamp of now
        		
        		ListIterator<SetOfElements> li = l.listIterator();
        		while(li.hasNext()) { //Iterate the list
        			SetOfElements elts = li.next();          			
    				if(now - elts.timestamp >= 2000) {			//if the message is older than 2 second
    					li.remove();							//we remove the element
    					this.writeSocket(elts.key, elts.buffer);//write the message in the client socket
    				}
    				else
    					break;//don't iterate through all elements because we know they are sorted from the older to the newer so all the following will be below 2 second
        		}
        	}
        }
        
        public void writeSocket(SelectionKey k, ByteBuffer b) {

        	SocketChannel client =  (SocketChannel) k.channel(); // gather the client socket
        	try {
				client.write(b);								//write the message to the client
			} catch (IOException e) {
				e.printStackTrace();
			}
        }
    };
}