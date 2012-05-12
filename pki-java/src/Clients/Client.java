package Clients;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import CryptoAPI.PathCheckerOCSP;
import CryptoAPI.PathCheckerSimple;
import CryptoAPI.PathChecking;
import Ldap.ldaputils;
import Utils.Config;


public class Client {
	
	boolean isServer = false;
	ServerSocket server_sock;
	Socket s;
	Socket s_cli;
	DataOutputStream out;
	DataInputStream in;
	KeyStore ks;
	X509Certificate myCert;
	PrivateKey myKey;
	X509Certificate caSign;
	X509Certificate rootCert;
	X509Certificate interCert;
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
				// Open the keystore
				ks = KeyStore.getInstance(KeyStore.getDefaultType());
				this.keystorepath = Config.get("KS_PATH_USER","mykeystore.ks");
				this.keystorepass = Config.get("KS_PASS_USER","passwd");
				ks.load(new FileInputStream(this.keystorepath), this.keystorepass.toCharArray());
				//------------
				
				//Get all the required certificates
				this.aliascert = Config.get("CLIENT_CERT_ALIAS","mycert");
				this.aliaskey = Config.get("CLIENT_KEY_ALIAS","mykey");
				this.keypass = Config.get("CLIENT_KEY_PASS","mypass");
				if(ks.containsAlias(aliascert)) //Take them only if they exists
					myCert = (X509Certificate) ks.getCertificate(aliascert);
				if(ks.containsAlias(aliaskey))
					myKey = (PrivateKey) ks.getKey(aliaskey, this.keypass.toCharArray());
				caSign = (X509Certificate) ks.getCertificate("CA_SigningOnly_Certificate");
				rootCert = (X509Certificate) ks.getCertificate(Config.get("KS_ALIAS_CERT_CA",""));
				interCert = (X509Certificate) ks.getCertificate(Config.get("KS_ALIAS_CERT_CA_INTP",""));
				//-------
			}
			catch(FileNotFoundException e) {
					System.out.println(this.keystorepath+" not found!");
					System.out.println("Please run the Client setup or change keystore path in config file.");
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public void saveKeystoreStat() { // Method used to save physically in the file all the changes that have been made on the keystore
		try {
			this.ks.store(new FileOutputStream(this.keystorepath), this.keystorepass.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void menuSelection() throws QuitException { //Method in which the program will be jailed until the user press 6 or a QuitException is raised.
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
			    System.out.print("Choice: ");
			    val = ClientUtils.readIntKeyboard();
			    if(val == null)
			    	continue;
			    else
			    	if(val >= 1 && val <=6) // Loop while the value read is not been the given value
			    		isOK= false;
			}while (isOK);
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		
		//Call the handler with the right value read (more clean to put it in another method)
		this.menuNumberHandler(val);
		
	}
	
	public void menuNumberHandler(int num) throws QuitException {
		try {
			switch(num) { //Do a switch on the value received
			case(1):
				//---------------------- CSR REQUEST --------------------------
				if(this.myCert ==null && this.myKey==null) { // Do the following only if the user does not have a certificate yet.
					ConnectionCSR cli = new ConnectionCSR(Config.get("IP_RA", "localhost"), new Integer(Config.get("PORT_RA","5555"))); //Instantiate the client
					try {
						cli.connect();
					}catch(Exception e) {
						System.out.println("Cannot connect to RA "+Config.get("IP_RA", "localhost")+":"+Config.get("PORT_RA","5555")+e.getMessage());
						break;
					}
					cli.run(); //Run the client that will connect to the RA and do all the stuff.
					if(cli.finishedWell()) { //Received if it ended successfully. If not print the error message that the client will have set.
						System.out.println("OK");
						cli.storeCertAndKey(this.ks, this.aliascert, this.aliaskey, this.keypass); //Call a method that will had the new certificate/key in our keystore.
						this.myCert = (X509Certificate) ks.getCertificate(this.aliascert); //Read them back from the keystore
						this.myKey = (PrivateKey) ks.getKey(aliaskey, keypass.toCharArray());
					}
					else
						System.out.println(cli.getErrorMessage()); //Print the error message if it failed
					cli.close();
				}
				else
					System.out.println("The certificate with alias: "+this.aliascert+" and "+this.aliaskey+" already exists !");
				break;
				//------------------------------------------------------------------------
			case(2):
				//----------------------- Certificate revocation  ----------------------------
				if(this.myCert != null) { // Do it if we have our certificate
					ConnectionRevocation cli = new ConnectionRevocation(Config.get("IP_RA", "localhost"), new Integer(Config.get("PORT_RA","5555")));
					try {
						cli.connect();
					}catch(Exception e) {
						System.out.println("Cannot connect to RA "+Config.get("IP_RA", "localhost")+":"+Config.get("PORT_RA","5555")+e.getMessage());
						break;
					}
					cli.run(); //Launch the client that will  read in our password send it to the RA and 
					if(cli.finishedWell()) {
						System.out.println("OK");
						ks.deleteEntry(aliascert); // If it ended successfully we delete the our revoked certificate from the keystore
						ks.deleteEntry(aliaskey);
						saveKeystoreStat(); // And save the keystore state.
						this.myCert =null;
						this.myKey = null;
					}
					else
						System.out.println(cli.getErrorMessage());
					cli.close();
				}
				else
					System.out.println("Your certificate '"+this.aliascert+"' not found in the keystore");
				break;
				//------------------------------------------------------------------------------------
			case(3):
				//------------------------- Download a Certificate --------------------------------
		          getClientCertificate(); //Call the generic method
		          break;
		          //-----------------------------------------------------------------------------------------
			case(4):
				//----------------------- Start a session as CLIENT ----------------------------
				if(this.myCert == null || this.myKey == null) { // Do it if we have our keys/certs
					System.out.println("Your certificate '"+this.aliascert+"' or key '"+this.aliaskey+"' not in the keystore");
					return;
				}
				
				X509Certificate clientcert = getClientCertificate(); //Read in the person we want to talk to.
				if (clientcert == null) // We have not been able to retreive his certificate
					return;
				if (!(verificationBeforeConnection(clientcert))) // Check if the certificate is valid
					return;
				
				System.out.print("Please enter IP to connect to: ");
				String ip = ClientUtils.saisieString(); // Read the IP address
				Integer port = new Integer(Config.get("PORT_LISTEN", "7000")); // We use the default port defined in the config file

				needhamcli = new NeedhamShroederClient(ip, port, this.s,this.isServer,this.myCert,this.myKey,clientcert); //Instantiate our NeedhamShroederClient
				try {
					needhamcli.connect(); // Connect to the peer
				}catch(Exception e) {
					System.out.println("Cannot connect to Client "+Config.get("IP_RA", "localhost")+":"+Config.get("PORT_RA","5555")+e.getMessage());
					break;
				}
				needhamcli.run(); // Run the client that will do the needham exchange, generating, checking nonce ..
				if(needhamcli .finishedWell())
					System.out.println("Needham Shroeder exchange OK"); //If this is OK go further for the chat
				else {
					System.out.println(needhamcli .getErrorMessage());
					break;
				}
				
				sessionkey =needhamcli .getSessionKey(); //Get the session key that will be used for the chat session (it is generated using the two nonce)
				this.s = needhamcli.getSocketBack(); //The socket has been instantiated in the Needham client so to start chat without disconnecting we have to get it back in this class.
				
				System.out.println("----- Chat -----");
				chat = new ConnectionChat(ip, port, this.s, sessionkey); //Instantiate the Chat client with the session key and the socket ALREADY OPENED !
				chat.bind(); //We call the bind method instead of connect.
				chat.run(); // Run the client
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
				//--------------------------- Start session as SERVER ---------------------------------
				// Work almost like the client case
				if(this.myCert == null || this.myKey == null) {
					System.out.println("Your certificate '"+this.aliascert+"' or key '"+this.aliaskey+"' not in the keystore");
					return;
				}
				
				X509Certificate clientC = getClientCertificate();
				if (clientC == null)
					return;
				if (!(verificationBeforeConnection(clientC)))
					return;
			
				if(this.server_sock != null) { //If the ServerSocket as already been instantiated we close all the connection to reinstantiate them.
					this.s_cli.close();
					this.server_sock.close();
					this.server_sock = null;
				}
				
				
				this.server_sock = new ServerSocket(new Integer(Config.get("PORT_LISTEN", "7000"))); // Instantiate the new serverSocket
				
				System.out.println("Wait for a connection...");
				this.s_cli = this.server_sock.accept(); //Wait only one connection with the other peer.
				System.out.println("Client accepted: "+s_cli.getLocalSocketAddress().toString());
				
				this.isServer = true; // Set the self attributes to true, instead of false which is the default value
				Integer p = new Integer(Config.get("PORT_LISTEN","7000"));
				needhamcli = new NeedhamShroederClient("localhost", p, s_cli,this.isServer,this.myCert,this.myKey,clientC);
				needhamcli.bind();

				needhamcli.run();
				this.in = needhamcli.getInputStream();
				this.out = needhamcli.getOutputStream();
				if(needhamcli.finishedWell())
					System.out.println("Needham Shroeder exchange OK");
				else {
					System.out.println(needhamcli.getErrorMessage());
					break;
				}
				sessionkey = needhamcli.getSessionKey();
				s_cli = needhamcli.getSocketBack();
				
				System.out.println("----- Chat -----");
				chat = new ConnectionChat("localhost", p, s_cli, sessionkey);
				chat.bind();
				chat.run();
				chat.close();
				if (chat.finishedWell())
					System.out.println("Done.");
				else {
					System.out.println(chat.getErrorMessage());
					throw new QuitException();
				}
				this.isServer = false;
				this.server_sock.close();
				this.server_sock = null;
				s_cli.close();
				break;
				//-----------------------------------------------------------------------------------------------
			case(6):
				throw new QuitException();
			default:
				//In Theory Impossible
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
			if (!(c==null)) {
				System.out.println("Certificate downloaded on LDAP");
				ks.setCertificateEntry(uid, c);
				saveKeystoreStat();
			}
			else
				System.out.println("Certificate not found for the given user.");
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
			isValid = PathChecking.checkPathUserCertificate(c, false, new PathCheckerSimple(), new X509Certificate[] { interCert }, rootCert);
		}
		else
			isValid = PathChecking.checkPathUserCertificate(c, false, new PathCheckerOCSP(caSign), new X509Certificate[] { interCert }, rootCert);
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
				System.out.println("End.");
				break;
			}
		}
	}
	
	public static void main(String[] args) {
		Client cli = new Client();
		cli.run();
	}
}
