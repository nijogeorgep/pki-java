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

import com.sun.corba.se.spi.ior.MakeImmutable;

import CryptoAPI.PathCheckerOCSP;
import CryptoAPI.PathCheckerSimple;
import CryptoAPI.PathChecking;
import Ldap.ldaputils;
import Utils.Config;


public class Client {
	
	boolean isServer = false;
	ServerSocket server_sock;
	Socket s;
	DataOutputStream out;
	DataInputStream in;
	KeyStore ks;
	X509Certificate myCert;
	PrivateKey myKey;
	X509Certificate caSign;
	String keystorepath;
	String keystorepass;
	String aliascert;
	String aliaskey;
	String keypass;
	byte[] sessionkey;
	NeedhamShroederClient needhamcli;
	ConnectionChat chat;
	
	public Client() {
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
			caSign = (X509Certificate) ks.getCertificate("CA_SigningOnly_Certificate");
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
			    System.out.println("Menu: ");
			    System.out.println("1 - Create certificate");
			    System.out.println("2 - Revoke certificate");
			    System.out.println("3 - Get a certificate");
			    System.out.println("4 - Start chat as client");
			    System.out.println("5 - Start chat as server");
			    System.out.println("6 - Quit");
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
				//---------------------- CSR REQUEST --------------------------
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
				//------------------------------------------------------------------------
			case(2):
				//----------------------- Revocation de Certificat ----------------------------
				//On appelle la méthode qui permet de révoquer un certificat
				if(this.myCert != null) {
					ConnectionRevocation cli = new ConnectionRevocation(Config.get("IP_RA", "localhost"), new Integer(Config.get("PORT_RA","5555")));
					cli.connect();
					cli.run();
					if(cli.finishedWell()) {
						System.out.println("OK");
						ks.deleteEntry(aliascert);
						ks.deleteEntry(aliaskey);
						saveKeystoreStat();
					}
					else
						System.out.println(cli.getErrorMessage());
					cli.close();
				}
				break;
				//------------------------------------------------------------------------------------
			case(3):
				//------------------------- Telecharger un Certificat --------------------------------
		          getClientCertificate();
		          break;
		          //-----------------------------------------------------------------------------------------
			case(4):
				//----------------------- Demarrer une session CLIENT ----------------------------
				X509Certificate clientcert = getClientCertificate();
				if (!(verificationBeforeConnection(clientcert)))
					return;
				
				System.out.print("Please enter IP to connect to: ");
				String ip = ClientUtils.saisieString();
				
				X509Certificate certB = (X509Certificate) this.ks.getCertificate("personne1_certificat");
				needhamcli = new NeedhamShroederClient(ip, 5555, this.s,this.isServer,this.myCert,this.myKey,clientcert);
				//cli.bind();
				needhamcli .connect();
				needhamcli .run();
				//this.in = this.needhamcli .getInputStream();
				//this.out = this.needhamcli .getOutputStream();
				if(needhamcli .finishedWell())
					System.out.println("Needham Shroeder exchange OK");
				else
					System.out.println(needhamcli .getErrorMessage());
				
				sessionkey =needhamcli .getSessionKey();
				this.s = needhamcli.getSocketBack();
				
				System.out.println("----- Chat -----");
				chat = new ConnectionChat("localhost", 5555, this.s, sessionkey);
				chat.bind();
				chat.run();
				chat.close();
				if (chat.finishedWell())
					System.out.println("Done.");
				else {
					System.out.println(chat.getErrorMessage());
					throw new QuitException();
				}
				//cli.close();
				break;
				//---------------------------------------------------------------------------------------------
			case(5):
				//--------------------------- Demarrer session SERVER ---------------------------------
				//On démarre la socket en tant que server
				this.isServer = true;
			
				X509Certificate clientC = getClientCertificate();
				if (!(verificationBeforeConnection(clientC)))
					return;
			
				//to delete
				//this.myCert = (X509Certificate) this.ks.getCertificate("personne1_certificat");
				//this.myKey = (PrivateKey) this.ks.getKey("personne1_private", "monpassP1".toCharArray());
				X509Certificate certBB = (X509Certificate) ks.getCertificate("robin1_certificat");
				
				this.server_sock = new ServerSocket(5555);
				
				System.out.println("Wait for a connection...");
				Socket s_cli = this.server_sock.accept();
				System.out.println("Client accepted: "+s_cli.getLocalSocketAddress().toString());
				
				needhamcli = new NeedhamShroederClient("localhost", 7777, s_cli,this.isServer,this.myCert,this.myKey,clientC);
				needhamcli.bind();
				//cli2.connect();
				needhamcli.run();
				this.in = needhamcli.getInputStream();
				this.out = needhamcli.getOutputStream();
				if(needhamcli.finishedWell())
					System.out.println("Needham Shroeder exchange OK");
				else
					System.out.println(needhamcli.getErrorMessage());
				
				sessionkey = needhamcli.getSessionKey();
				s_cli = needhamcli.getSocketBack();
				
				System.out.println("----- Chat -----");
				chat = new ConnectionChat("localhost", 5555, s_cli, sessionkey);
				chat.bind();
				chat.run();
				chat.close();
				if (chat.finishedWell())
					System.out.println("Done.");
				else {
					System.out.println(chat.getErrorMessage());
					throw new QuitException();
				}
				
				//cli2.close();
				break;
				//-----------------------------------------------------------------------------------------------
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
	
	
	public X509Certificate getClientCertificate() {
		try {
			String id = ClientUtils.readIdentity();
			String uid = ldaputils.getUIDFromSubject(id);
			if (uid == null) {
				return null;
			}
			if(ks.containsAlias(uid)) {
				if (ks.isCertificateEntry(uid)) {
					System.out.println("Certificat found on keystore");
					int choice = ClientUtils.makeChoice("Download anyway ?", "1.Yes", "2.No");
					if (choice == 2) {
						return (X509Certificate) ks.getCertificate(uid);
					}
				}
			}
			X509Certificate c =  ldaputils.getCertificate(uid);
			System.out.println("Certificate downloaded on LDAP");
			ks.setCertificateEntry(uid, c);
			saveKeystoreStat();
			return c;
		}
		catch(Exception e) {
			return null;
		}
	}
	
	public boolean verificationBeforeConnection(X509Certificate c) {
		if(c == null) {
			System.out.println("Not able to retreive certificate");
			return false;
		}
		int choice = ClientUtils.makeChoice("Select cert validation method:", "CRL", "OCSP");
		boolean isValid;
		try {
		if (choice == 1) {
			isValid = PathChecking.checkPathUserCertificate(c, false, new PathCheckerSimple());
		}
		else
			isValid = PathChecking.checkPathUserCertificate(c, false, new PathCheckerOCSP(caSign));
		}
		catch(Exception e) {
			e.printStackTrace();
			return false;
		}
		if (!(isValid)) {
			System.out.println("The certificate is not valid !");
			return false;
		}
		return true;
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
		Client cli = new Client();
		cli.run();
	}
}
