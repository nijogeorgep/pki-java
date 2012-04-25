package Clients;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Scanner;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import sun.security.krb5.Config;

import Ldap.LDAP;
import Ldap.ldaputils;
import Playground.setup_ca;


public class Client {
/*
 * Se connecte au server localhost situé sur le port 5555 et permet de dialoguer via la serialisation d'objet String
 */
	String message = null;
	boolean isServer = false;
	ServerSocketChannel server_sock;
	static SocketChannel s;
	private static String ip = "localhost" ;
	static KeyStore ks ;
	static String aliasKS = null;
	
	public Client() {}
	
	public Client(boolean server) {
		this.isServer = server;
	}
	
	public static void main(String[] args) throws UnknownHostException, IOException, ClassNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException { // main se contente de créer le objet ChatClient et de lancer
		
		/* ########## TODO #########
		 * Avant de lancer un quelconque chat je propose les options suivantes:
		 *  1. Création d'un certificat (si il n'existe pas dans notre KeyStore) et donc géneration de la CSR envoie au RA attente réponse etc..
		 *  2. Révocation de notre certificat si il a été corrompu d'une manière ou d'une autre
		 *  3. Demarrer un chat en tant qu'hôte ou client (et dépendant demander IP + port)
		 *  4. Récupérer le certificat d'une personne donnée auprès du Repository (pas vraiment utile sauf pour les tests)
		 *########################*/
		
		//On crée le nouvel objet client
		Client client = new Client();
		
		//On va chercher l'Alias du client dans le fichier de config si il existe
		String chercherAlias = Utils.Config.get("ALIAS", "defaultval");
		if(!chercherAlias.equals("defaultval"))
		  aliasKS = chercherAlias;
		
		//creation du keystore
	  ks = KeyStore.getInstance(KeyStore.getDefaultType());
	  try {
      ks.load(new FileInputStream("src/Clients/mykeystore.ks"), "pierre".toCharArray());
    }
    catch (FileNotFoundException e) {
      System.out.println("First launch !");
      ks.load(null);
    }

		char al ;
		
		do
		{
    System.out.println("Options ");
    System.out.println("1 - Cr�er un certificat ");
    System.out.println("2 - R�voquer un certificat ");
    System.out.println("3 - Recuperer un certificat ");
    System.out.println("4 - Demarrer en chat en tant que client ");
    System.out.println("5 - Demarrer en chat en tant que serveur ");
    System.out.println("6 - Quitter ");
    
    al = saisie();
    
      switch(al)
      {
        case('1'):// creation d'un certificat
          if(ks.containsAlias(aliasKS))
          {
            //creation CSR
            PKCS10CertificationRequest createCertReq = creerCertificat();
            System.out.println(createCertReq.toString());
            //connnection et envoi au RA du CSR.
            Socket raSock = new Socket("localhost",7000);
            ObjectOutputStream stream = new ObjectOutputStream(raSock.getOutputStream());
            stream.writeObject(createCertReq.getEncoded());
            
            //identification
            //TODO chiffrer le mdp avant l'envoi.
            System.out.println("Saisissez votre mot de passe");
            String pwd = saisieString();
            stream.writeObject(pwd);
            
            ObjectInputStream inStream1 = new ObjectInputStream(raSock.getInputStream());
            Boolean pwdCorrect = inStream1.readBoolean();
            if(pwdCorrect)
            {
              //Le RA renvoi un certificat.
              ObjectInputStream inStream = new ObjectInputStream(raSock.getInputStream());
              X509Certificate c = (X509Certificate) inStream.readObject();
              
              //Enregistrement du certificat dans le keystore.
              ks.setCertificateEntry(aliasKS, c);
              System.out.println(c.toString());
            }
            else
            {
             System.out.println("erreur de mot de passe."); 
            }    
          }
          else
          {
            System.out.println("Vous poss�dez d�j� un certificat. R�voquez le avant d'en" +
            		"creer un nouveau. ");
          }
          break ; 
        case('2'): // r�vocation d'un certificat    
          //Connection au RA et envoi de l'UID du certificat du client
          Socket raSock = new Socket("localhost",7000);       
          OutputStream stream = raSock.getOutputStream();
          X509Certificate  cert = (X509Certificate)ks.getCertificate(aliasKS);
          System.out.println("Serial:"+cert.getSerialNumber());
         
          stream.write(cert.getSerialNumber().toByteArray());   

          
          //identification
          //TODO chiffrer le mdp avant l'envoi.
          System.out.println("Saisissez votre mot de passe");
          String pwd = saisieString();
          stream.write(pwd.getBytes());
          InputStream inStream1 =raSock.getInputStream();
          int pwdCorrect = inStream1.read();
          if(pwdCorrect == 1)
          {
            //R�ponse du RA ( Certificat revoqu� ou non )
            ObjectInputStream inStream = new ObjectInputStream(raSock.getInputStream());
            String s = inStream.readLine();
            System.out.println(s);
          }
          else
          {
            System.out.println("erreur de mot de passe."); 
          }
          break ; 
        case('3'):// r�cup�ration d'un certificat
            System.out.println("Donnez l'UID de votre correspondant");
            String uid = saisieString();
            //LDAP recheche un certificat avec l'uid qu'on lui a donn�.
            X509Certificate c = ldaputils.getCertificate(uid);
            //ajout du certificat dans le keystore.
            ks.setCertificateEntry(Utils.Config.get("ALIAS", "default_val"), c);
            System.out.println("Certificat ajout�");
            break ; 
        case('4'):// connection en mode client
          client.connect(ip,5555,false);
          client.run();
            break ;
        case('5')://connection en mode serveur
          client.isServer = true ;
          client.connect(ip,5555,false);
          client.run();
            break ;
        case('6')://fin
          break;
      }
    
		}while(!(al=='6'));
    
    /*
		client.connect(); // Etablit la connection par socket que ce soit client ou server
		/* ########## TODO ##########
		 * ici on est connecté avec le client il faut donc :
		 * - recevoir et envoyé nos certificats respectifs (je pense celui qui se connect envoie en premier)
		 * - (Inutile mais faut le faire) Voir si notre CRL du CA associé n'est pas perimé (si oui télécharger le nouveau) et vérifier que le certificat n'en fait pas parti)
		 * - Faire une requête OCSP au Repository pour vérifier (en live) que le certificat n'est pas périmé.
		 * - A partir d'ici je propose le client attend la réponse du server (j'accepte ta session ou je te fais pas confiance je ferme la connection), puis le client fait de même avec le server
		 * - Si tout est bon a partir d'ici les deux clients en P2P (qui sont en fait un client/servers) s'échangent une clé de session avec leurs clés publique qui sera utilisées pour chiffrer chaque message
		 *#########################*/
		//client.run(); // lance le chat
	}	
	

  
  private static PKCS10CertificationRequest creerCertificat()
  {
    System.out.println("Nom du certificat : ");
    String nomCertif = saisieString();
    KeyPair kp;
    try
    {
      kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
      try
      {
        return setup_ca.generate_csr(nomCertif,kp);
      }
      catch (NoSuchAlgorithmException e)
      {
        e.printStackTrace();
      }
      catch (OperatorCreationException e)
      {
        e.printStackTrace();
      }
    }
    catch (NoSuchAlgorithmException e1)
    {
      e1.printStackTrace();
    } ;
    return null;
    
    
  }
  
  private static char saisie()
  {
    char io = ' ';
    Scanner sc = new Scanner(System.in);
    io = sc.next().charAt(0);
    return io;
  }
  private static String saisieString()
  {
    Scanner sc = new Scanner(System.in);
    String s = null;
    s = sc.nextLine();
    return s;
  }
  
	public void connect(String ip,int numPort, boolean blocking) {
		try {
			if(this.isServer) {
				server_sock = ServerSocketChannel.open();
				server_sock.socket().bind(new InetSocketAddress(ip,5555));
				s = server_sock.accept();
		        s.configureBlocking(blocking); // pas fondamentalement utile
			}
			else { //is client
				s = SocketChannel.open();
				s.configureBlocking(blocking); //pas obligatoire
				s.connect(new InetSocketAddress(ip,5555));
				while(! s.finishConnect()) { }//si non bloquant on doit s'assurer que la connexion s'est bien établie
			}
		}
		catch (IOException e) {
			System.out.println("Could not establish connection");
		}
		
	}
	
	
	public void run() {
	  
	  
	  
	  
		/*
		StringSerializer ser = new StringSerializer();	
		ObjectChannel chan = new ObjectChannel<String>(ser, s);
		
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
			/*	System.out.println(mess_received);
			}
		}
		catch (IOException e) {
			System.out.println("Connection closed unexpectedly");
		}*/
	}
	
	
}
