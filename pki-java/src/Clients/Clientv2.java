package Clients;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import Ldap.ldaputils;
import Utils.Config;


public class Clientv2 {
	
	boolean isServer = false;
	ServerSocket server_sock;
	Socket s;
	DataOutputStream out;
	DataInputStream in;
	KeyStore ks;
	X509Certificate myCert;
	PrivateKey myKey;
	String keystorepath;
	String keystorepass;
	String aliascert;
	String aliaskey;
	String keypass;
	
	public Clientv2() {
		try {
			try {
				ks = KeyStore.getInstance(KeyStore.getDefaultType());
				this.keystorepath = Config.get("USER_KEYSTORE_PATH","mykeystore.ks");
				this.keystorepass = Config.get("USER_KEYSTORE_PASS","passwd");
				ks.load(new FileInputStream(this.keystorepath), this.keystorepass.toCharArray());
			}
			catch(FileNotFoundException e) {
					ks.load(null);
			} catch (Exception e) {
				e.printStackTrace();
			}
			this.aliascert = Config.get("CLIENT_CERT_ALIAS","mycert");
			this.aliaskey = Config.get("CLIENT_KEY_ALIAS","mykey");
			this.keypass = Config.get("CLIENT_KEY_PASS","mypass");
			myCert = (X509Certificate) ks.getCertificate(aliascert);
			myKey = (PrivateKey) ks.getKey(aliaskey, this.keypass.toCharArray());
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public void saveKeystoreStat() {
		try {
			this.ks.store(new FileOutputStream(this.keystorepath), this.keystorepass.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void menuSelection() throws QuitException {
		Integer val = null;
		boolean isOK = true;
		try {
			
			do {
			    System.out.println("Options ");
			    System.out.println("1 - Cr�er un certificat ");
			    System.out.println("2 - R�voquer un certificat ");
			    System.out.println("3 - Recuperer un certificat ");
			    System.out.println("4 - Demarrer en chat en tant que client ");
			    System.out.println("5 - Demarrer en chat en tant que serveur ");
			    System.out.println("6 - Quitter ");
			    val = ClientUtils.readIntKeyboard();
			    if(val == null)
			    	continue;
			    else
			    	if(val >= 1 && val <=6)
			    		isOK= false;
			}while (isOK);
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		
		//appelle le handler avec le numero récupéré (j'aurais pu le mettre ici mais c'est plus propre dans une autre méthode
		this.menuNumberHandler(val);
		
	}
	
	public void menuNumberHandler(int num) throws QuitException {
		try {
			System.out.println("Val: "+num);
			switch(num) {
			case(1):
				if(this.myCert ==null && this.myKey==null) {
					ConnectionCSR cli = new ConnectionCSR(Config.get("IP_RA", "localhost"), new Integer(Config.get("PORT_RA","5555")));
					cli.connect();
					cli.run();
					if(cli.finishedWell()) {
						System.out.println("OK");
						cli.storeCertAndKey(this.ks, this.aliascert, this.aliaskey, this.keypass);
					}
					else
						System.out.println(cli.getErrorMessage());
					cli.close();
				}
				else
					System.out.println("The certificate with alias: "+this.aliascert+" and "+this.aliaskey+" already exists !");
				break;
			case(2):
				//On appelle la méthode qui permet de révoquer un certificat
				if(this.myCert != null) {
					ConnectionRevocation cli = new ConnectionRevocation(Config.get("IP_RA", "localhost"), new Integer(Config.get("PORT_RA","5555")));
					cli.connect();
					cli.run();
					if(cli.finishedWell()) {
						System.out.println("OK");
					}
					else
						System.out.println(cli.getErrorMessage());
					cli.close();
				}
				break;
			case(3):
		          String surname,commonname;
		          System.out.println("Entrez votre nom");
		          surname = ClientUtils.saisieString();
		          System.out.println("Entrez votre prenom");
		          commonname = ClientUtils.saisieString();
		          String identite = commonname.replace(" ", "-") + " " + surname.replace(" ", "-");
		          
		          String uid = ldaputils.getUIDFromSubject(identite);
		          System.out.println("CN="+identite);
		          System.out.println(uid);
		          X509Certificate c = ldaputils.getCertificate(uid);
		          // ajout du certificat dans le keystore.
		          System.out.println(c.toString());
		          ks.setCertificateEntry(Utils.Config.get("ALIAS", "default_val"), c);
		          System.out.println("Certificat ajout�");
		          break;
			case(4):
				//lit l'identité de la personne
				//on récupère l'uid 
				//Si l'uid existe dans le keystore on récupère le cert de B
				//Sinon on le télécharge sur ldap
				X509Certificate certB = (X509Certificate) this.ks.getCertificate("personne1_certificat");
				NeedhamShroederClient cli = new NeedhamShroederClient("localhost", 5555, this.s,this.isServer,this.myCert,this.myKey,certB);
				//cli.bind();
				cli.connect();
				cli.run();
				this.in = cli.getInputStream();
				this.out = cli.getOutputStream();
				if(cli.finishedWell())
					System.out.println("It's all right client");
				else
					System.out.println(cli.getErrorMessage());
				
				//this.out.write("Hello".getBytes());
				cli.close();
				break;
			case(5):
				//On démarre la socket en tant que server
				this.isServer = true;
				X509Certificate certC = (X509Certificate) this.ks.getCertificate("personne1_certificat");
				PrivateKey key = (PrivateKey) this.ks.getKey("personne1_private", "monpassP1".toCharArray());
				this.server_sock = new ServerSocket(5555);
				System.out.println("Wait for a connection...");
				Socket s_cli = this.server_sock.accept();
				System.out.println("Client accepted: "+s_cli.getLocalSocketAddress().toString());
				
				NeedhamShroederClient cli2 = new NeedhamShroederClient("localhost", 7777, s_cli,this.isServer,certC,key,this.myCert);
				cli2.bind();
				//cli2.connect();
				cli2.run();
				this.in = cli2.getInputStream();
				this.out = cli2.getOutputStream();
				if(cli2.finishedWell())
					System.out.println("It's all right server");
				else
					System.out.println(cli2.getErrorMessage());
				//this.out.write("Hello".getBytes());
				cli2.close();
				break;
			case(6):
				throw new QuitException();
			default:
				//Théoriquement impossible
			}
			
		}catch(QuitException e) {
			throw new QuitException();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	
	public void run() {
		for(;;) {
			try {
				this.menuSelection();
			}
			catch(QuitException e) {
				System.out.println("in quit !");
				break;
			}
		}
	}
	
	public static void main(String[] args) {
		Clientv2 cli = new Clientv2();
		cli.run();
	}
}
