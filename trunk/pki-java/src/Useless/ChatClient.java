package Useless;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import java.util.Scanner;

import Utils.ObjectChannel;
import Utils.StringSerializer;

public class ChatClient {
/*
 * Se connecte au server localhost situé sur le port 5555 et permet de dialoguer via la serialisation d'objet String
 */
	String message = null;
	InputThread th;
	
	public static void main(String[] args) { // main se contente de créer le objet ChatClient et de lancer
		ChatClient client = new ChatClient();
		try {
			client.run();
		}
		catch (IOException e) {
			System.out.println("Connection closed unexpectedly");
		} catch (InterruptedException e) {
		}
	}	
	
	
	public void run() throws IOException, InterruptedException {

		SocketChannel s = SocketChannel.open();
		s.configureBlocking(false); //pas obligatoire
		s.connect(new InetSocketAddress("localhost",5555));
		while(! s.finishConnect()) { //si non bloquant on doit s'assurer que la connexion s'est bien établie
		}
		
		StringSerializer ser = new StringSerializer();	
		ObjectChannel<String> chan = new ObjectChannel<String>(ser, s);
		
		th = new InputThread(this.message, chan); //Thread interne qui va lire les entrees au clavier et les envoyer indépendamment de la lecture de la socket
		th.start();
		
		for(;;) { // le thread principal est bloqué dedans pour la lecture dans la socket

			String mess_received= null;
			while(mess_received == null) {
				mess_received = chan.read(); //on lit tant que l'on ne récupère pas un vrai objet
			}
			System.out.println(mess_received);
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
