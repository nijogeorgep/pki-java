package Clients;

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

import Utils.Config;


public class Clientv2 {
	
	boolean isServer = false;
	ServerSocket server_sock;
	Socket s;
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
				break;
			case(3):
				//On appelle la méthode qui permet de chercher un certificat sur le ldap
				break;
			case(4):
				//On démarre la socket en tant que client et on essaye de démarrer une session
				/*this.s = new Socket("lcoalhsot", 34);
				NeedhamShroederClient cli = new NeedhamShroederClient(s);
				clir.run();
				if cli.isOK() {
					s.write
				}*/
				break;
			case(5):
				//On démarre la socket en tant que server
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
