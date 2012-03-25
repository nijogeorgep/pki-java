package Clients;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Scanner;

import Utils.ObjectChannel;
import Utils.StringSerializer;

public class Client {
/*
 * Se connecte au server localhost situé sur le port 5555 et permet de dialoguer via la serialisation d'objet String
 */
	String message = null;
	InputThread th;
	boolean isServer = false;
	ServerSocketChannel server_sock;
	SocketChannel s;
	
	public Client() {}
	public Client(boolean server) {
		this.isServer = server;
	}
	
	public static void main(String[] args) { // main se contente de créer le objet ChatClient et de lancer
		
		/* ########## TODO #########
		 * Avant de lancer un quelconque chat je propose les options suivantes:
		 *  1. Création d'un certificat (si il n'existe pas dans notre KeyStore) et donc géneration de la CSR envoie au RA attente réponse etc..
		 *  2. Révocation de notre certificat si il a été corrompu d'une manière ou d'une autre
		 *  3. Demarrer un chat en tant qu'hôte ou client (et dépendant demander IP + port)
		 *  4. Récupérer le certificat d'une personne donnée auprès du Repository (pas vraiment utile sauf pour les tests)
		 *########################*/
		
		//On crée le nouvel objet client
		Client client = new Client();
		
		client.connect(); // Etablit la connection par socket que ce soit client ou server
		/* ########## TODO ##########
		 * ici on est connecté avec le client il faut donc :
		 * - recevoir et envoyé nos certificats respectifs (je pense celui qui se connect envoie en premier)
		 * - (Inutile mais faut le faire) Voir si notre CRL du CA associé n'est pas perimé (si oui télécharger le nouveau) et vérifier que le certificat n'en fait pas parti)
		 * - Faire une requête OCSP au Repository pour vérifier (en live) que le certificat n'est pas périmé.
		 * - A partir d'ici je propose le client attend la réponse du server (j'accepte ta session ou je te fais pas confiance je ferme la connection), puis le client fait de même avec le server
		 * - Si tout est bon a partir d'ici les deux clients en P2P (qui sont en fait un client/servers) s'échangent une clé de session avec leurs clés publique qui sera utilisées pour chiffrer chaque message
		 *#########################*/
		client.run(); // lance le chat

	}	
	
	public void connect() {
		try {
			if(this.isServer) {
				server_sock = ServerSocketChannel.open();
				server_sock.socket().bind(new InetSocketAddress(5555));
				s = server_sock.accept();
		        s.configureBlocking(false); // pas fondamentalement utile
			}
			else { //is client
				s = SocketChannel.open();
				s.configureBlocking(false); //pas obligatoire
				s.connect(new InetSocketAddress("localhost",5555));
				while(! s.finishConnect()) { }//si non bloquant on doit s'assurer que la connexion s'est bien établie
			}
		}
		catch (IOException e) {
			System.out.println("Could not establish connection");
		}
		
	}
	
	public void run() {
		
		StringSerializer ser = new StringSerializer();	
		ObjectChannel<String> chan = new ObjectChannel<String>(ser, s);
		
		th = new InputThread(this.message, chan); //Thread interne qui va lire les entrees au clavier et les envoyer indépendamment de la lecture de la socket
		th.start();
		try {
			for(;;) { // le thread principal est bloqué dedans pour la lecture dans la socket
	
				String mess_received= null;
				while(mess_received == null) {
					mess_received = chan.read(); //on lit tant que l'on ne récupère pas un vrai objet
				}
				/* ########## TODO ########
				 * ici on a reçue une string contenue dans mess_received il faut:
				 *  déchiffrer le message (avec notre clé privée)
				 *  vérifier la signature (avec la clé publique du client qu'il nous a envoyé)
				 * ######################*/
				System.out.println(mess_received);
			}
		}
		catch (IOException e) {
			System.out.println("Connection closed unexpectedly");
		}
	}
	
	// Thread indépendant qui les les entrées au clavier et les envoies !
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
					/*######### TODO #######
					 * ici on a lu une string au clavier il faut:
					 * chiffrer la string avec avec la clé public du client
					 * signer le message avec notre clé privée
					 *#####################*/
					while(!chan.write(mess)) { /*ne fait rien*/ }
				}
			}
			catch(IOException e) {
				//ne fait rien le thread va s'arreter tout seul
			}
		}
	}
}
