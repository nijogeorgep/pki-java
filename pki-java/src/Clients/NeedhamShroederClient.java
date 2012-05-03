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
	//prend en argument du constructeur la socket sur laquelle la connxion a été établie
	//execute chacune des phases de manière successive.
	boolean isServer;
	X509Certificate myCert;
	PrivateKey myKey;
	X509Certificate certB;
	
	public NeedhamShroederClient(String ip, Integer port, Socket s, boolean isserv, X509Certificate cA, PrivateKey kA, X509Certificate cB) {
		super(ip, port);
		this.s = s;
		this.isServer = isserv;
		this.myCert = cA;
		this.certB = cB;
		this.myKey = kA;
	}
	
	public void bind() {
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
			if(this.isServer)
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
		BigInteger nonceB = NeedhamSchroeder.generateNonce();
		byte[] step1received = this.read();
		byte[] step2 = NeedhamSchroeder.step2nonceAnonceBToA(this.certB, this.myKey, nonceB, step1received, true);
		this.out.write(step2);
		byte[] step3 = this.read();
		if(NeedhamSchroeder.step3received(myKey, nonceB, step3)) {
			this.finishedOK = true;
		}
		else {
			this.errormessage = "Nonce received not equal";
			this.finishedOK = false;
		}
	}
	
	public void runClient() throws IOException {
		BigInteger nonceA = NeedhamSchroeder.generateNonce();
		byte[] step1 = NeedhamSchroeder.step1nonceAToB(this.myCert, this.myKey, this.certB, nonceA);
		this.out.write(step1);
		byte[] step2received = this.read();
		byte[] step3 = NeedhamSchroeder.step3nonceBToB(this.myKey, this.certB, step2received, nonceA);
		if(step3 == null) {
			this.errormessage = "Nonce received not equal";
			this.finishedOK = false;
			return;
		}
		else
			this.out.write(step3);
		this.finishedOK = true;
	}
	
	public DataInputStream getInputStream() {
		return this.in;
	}
	
	public DataOutputStream getOutputStream() {
		return this.out;
	}
}
