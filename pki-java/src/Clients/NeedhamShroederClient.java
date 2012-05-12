package Clients;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import CryptoAPI.NeedhamSchroeder;

public class NeedhamShroederClient extends Connection{
	boolean isServer;
	X509Certificate myCert;
	PrivateKey myKey;
	X509Certificate certB;
	BigInteger nonceA;
	BigInteger nonceB;
	
	public NeedhamShroederClient(String ip, Integer port, Socket s, boolean isserv, X509Certificate cA, PrivateKey kA, X509Certificate cB) {
		super(ip, port);
		this.s = s;
		this.isServer = isserv;
		this.myCert = cA;
		this.certB = cB;
		this.myKey = kA;
	}
	
	public void bind() { //As connect but do not instantiate the socket, just retrieve the streams from it.
		try {
			this.out = new DataOutputStream(this.s.getOutputStream());
			this.in = new DataInputStream(new DataInputStream(this.s.getInputStream()));
		} catch (IOException e) {
			this.finishedOK = false;
		}
	}
	
	@Override
	public void run() {
		try {
			if(this.isServer) //Call two different method if we are client or server
				this.runServer();
			else
				this.runClient();
		}
		catch(IOException e) {
			this.errormessage = "Connection closed";
			this.finishedOK = false;
		}
	}
	
	public void runServer() throws IOException {
		nonceB = NeedhamSchroeder.generateNonce(); // Generate our nonce
		byte[] step1received = this.read(); //Read the nonceA sent by A
		
		this.nonceA = NeedhamSchroeder.getnonceAFromStep1(this.myKey, step1received); // Retreieve it
		if (this.nonceA == null) {
			this.errormessage = "Failed to decrypt NonceA with, PrivateKey";
			this.finishedOK = false;
			return;
		}
		byte[] step2 = NeedhamSchroeder.step2nonceAnonceBToA(this.certB, this.myKey, nonceB, step1received, true); // Create the answer composed of the two nonce
		if (step2 == null) {
			this.errormessage = "Failed to decrypt NonceA with, PrivateKey";
			this.finishedOK = false;
			return;
		}
		this.out.write(step2); // Send it
		byte[] step3 = this.read();// Read the reply
		if(NeedhamSchroeder.step3received(myKey, nonceB, step3)) { //If true it means A send us back the nonceB which means we is really who he pretend to be
			this.finishedOK = true;
		}
		else {
			this.errormessage = "Nonce received not equal or fail to decipher";
			this.finishedOK = false;
		}
	}
	
	public void runClient() throws IOException {
		nonceA = NeedhamSchroeder.generateNonce(); // Generate our nonce
		byte[] step1 = NeedhamSchroeder.step1nonceAToB(this.myCert, this.myKey, this.certB, nonceA); // Create the first packet
		this.out.write(step1); // Send it to B
		byte[] step2received = this.read(); // Receive the reply
		this.nonceB = NeedhamSchroeder.getNonceBFromStep2(this.myKey, step2received, nonceA); // Get the nonceB from the reply
		if (this.nonceB == null) { 
			this.errormessage = "NonceB received invalid";
			this.finishedOK = false;
			return;
		}
		byte[] step3 = NeedhamSchroeder.step3nonceBToB(this.myKey, this.certB, step2received, nonceA); // Check if the nonceA replied is ok, and by the same way create the reply
		if(step3 == null) {
			this.errormessage = "Nonce received not equal";
			this.finishedOK = false;
			return;
		}
		else
			this.out.write(step3); // Send the last packet which is the B challenge back
		this.finishedOK = true;
	}
	
	public byte[] getSessionKey() {
		return NeedhamSchroeder.generateSessionKey(nonceA, nonceB);
	}
	
	public DataInputStream getInputStream() {
		return this.in;
	}
	
	public DataOutputStream getOutputStream() {
		return this.out;
	}
	
	public Socket getSocketBack() {
		return this.s;
	}
}
