package Clients;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

import CryptoAPI.NeedhamSchroeder;
import CryptoAPI.SymmetricKeyManager;

public class ConnectionChat extends Connection{

	byte[] key;
	//boolean ended = false;
	//boolean diedOk = true;
	
	public ConnectionChat(String ip, Integer port, Socket s, byte[] key) {
		super(ip,port);
		this.s = s;
		this.key = key;
	}
	
	public void bind() {
		try {
			this.out = new DataOutputStream(this.s.getOutputStream());
			this.in = new DataInputStream(new DataInputStream(this.s.getInputStream()));
		} catch (IOException e) {
			this.finishedOK = false;
		}
	}
	
	
	public void run() {
		InputThread th = new InputThread(this.out);
		th.start();
		
		byte[] received;
		String inputmessage;
		try {
			for(;;) {
				if(th.ended)
					break;
				received = this.read();
				inputmessage = new String(SymmetricKeyManager.decipher(key, received));
				if (inputmessage.equals("bye")) {
					this.out.write(SymmetricKeyManager.cipher(key, "bye".getBytes()));
					if (!(th.ended))
						System.out.println("Client said bye\n Please Press a Key..");
					break;
				}
					System.out.println(inputmessage);
			}
			this.finishedOK = true;
			th.dieNow = true;
		}
		catch(IOException e) {
			if (th.ended)
				this.finishedOK = true;
			else {
				this.errormessage =  "Connnection closed";
				this.finishedOK = false;
			}
		}
		catch(Exception e ) {
			this.errormessage = "Error while trying to decrypt";
			this.finishedOK = false;
		}
		finally{
			th.dieNow = true;
			try {
				if(!(th.ended))
					th.join();
			} catch (InterruptedException e) {e.printStackTrace();}
		}
	}

	
	private class InputThread extends Thread implements Runnable {
		String outputmessage;
		OutputStream out;
		boolean ended = false;
		//boolean diedok = true;
		boolean dieNow = false;
		public InputThread(OutputStream o) {
			this.out = o;
		}
		
		public void run()  {
			try {
				Scanner sc = new Scanner(System.in);
				for(;;) {
					if(dieNow)
						break;
					outputmessage = sc.nextLine();
					if(outputmessage.equals("quit")) {
						this.out.write(SymmetricKeyManager.cipher(key,"bye".getBytes()));
						break;
					}
					else
						this.out.write(SymmetricKeyManager.cipher(key,outputmessage.getBytes()));
				}
			}
			catch(IOException e) {
				//ne fait rien le thread va s'arreter tout seul
			}
			catch(Exception e) {
				e.printStackTrace();
				System.out.println("Error while trying to encrypt");
			}
			finally {
				ended= true;
			}
		}
	}
	
	public static void main(String[] args) throws IOException {
		
		Socket s;
		
		try {
			ServerSocket server_sock = new ServerSocket(5555);
			System.out.println("Wait for a connection...");
			s = server_sock.accept();
		}
		catch(BindException e) {
			s = new Socket("localhost", 5555);
		}
		
		ConnectionChat chat = new ConnectionChat("localhost", 5555, s, NeedhamSchroeder.generateSessionKey(BigInteger.ONE, BigInteger.TEN));
		chat.bind();
		chat.run();
		chat.close();
		if (chat.finishedWell())
			System.out.println("Done.");
		else {
			System.out.println(chat.getErrorMessage());
		}
	}
	
}
