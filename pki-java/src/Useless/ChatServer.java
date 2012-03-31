package Useless;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Scanner;

import Utils.ObjectChannel;
import Utils.StringSerializer;

public class ChatServer {

	String message = null;
	InputThread th;
	
	public static void main(String[] args) { //Comme ChatClient ce main declare un nouvel objet ChatServer et le lance.
		ChatServer server = new ChatServer();
		try {
			server.run();
		}
		catch (IOException e) {
			System.out.println("Connection closed unexprectedly");
		} catch (InterruptedException e) {
		}
	}
	
	public void run() throws IOException, InterruptedException {

		ServerSocketChannel s = ServerSocketChannel.open();
		s.socket().bind(new InetSocketAddress(5555));
		StringSerializer ser = new StringSerializer();
		
		SocketChannel s_cli;
		s_cli = s.accept();
        s_cli.configureBlocking(false); // pas fondamentalement utile
		
		ObjectChannel<String> chan = new ObjectChannel<String>(ser, s_cli); //Creation de notre ObjectChannel avec la socket client
		
		th = new InputThread(this.message, chan); //Lance le thread de lecture au clavier et d'écriture dans la socket
		th.start();
		
		for(;;) {

			String mess= null;
			while(mess == null) {
				mess = chan.read();
			}			
			System.out.println(mess);
		}
	}
	
	private class InputThread extends Thread implements Runnable {
		String mess;
		ObjectChannel<String> chan;
		public InputThread(String s, ObjectChannel<String> c) {
			mess = s;
			chan = c;
		}
		public void run()  {
			try {
				Scanner sc = new Scanner(System.in);
				for(;;) {
					mess = sc.nextLine();
					while(!chan.write(mess)) { /*ne fait rien*/ }
				}
			}
			catch(IOException e) {
				//ne fait rien le thread va s'arreter tout seul
			}
		}
	}
}
