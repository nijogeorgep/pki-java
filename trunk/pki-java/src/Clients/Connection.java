package Clients;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public abstract class Connection {
	/*
	 * This is a Mother Class that manage everything about socket, connect read write and so on.
	 * So all classes that implement it does not have to worry about it.
	 * Moreover it setup an architecture to know if the client successfully ended or not via the errormessage attribute and the method finishedWell()
	 */
	String ip;
	Integer port;
	String errormessage;
	boolean finishedOK;
	Socket s;
	DataOutputStream out;
	DataInputStream in;
	
	public Connection(String ip, Integer port) {
		this.ip = ip;
		this.port =port;
	}
	
	public void connect() throws Exception {
			this.s = new Socket(this.ip, this.port);
			this.out = new DataOutputStream(s.getOutputStream()); // Gather to two Stream into local attributes
			this.in = new DataInputStream(s.getInputStream());
	}
	
	public abstract void run();
	
	public boolean finishedWell() {
		return finishedOK;
	}
	
	public String getErrorMessage() {
		return this.errormessage;
	}
	
	public byte[] read() throws IOException {
		byte[] res = new byte[4096]; //Create an array big enough to does not be obliged to join all pieces.
		int read = this.in.read(res); //Read in the socket and get back how many byte have been read
		if (read == -1) { //If nothing has been read raise an exception
				throw new IOException();
		}
		
		byte[] res_fitted = new byte[read]; //Now instantiate an array with the right size
		for (int i=0; i < read; i++) { //Copy everything back into
			res_fitted[i] = res[i];
		}
		return res_fitted;
	}
	
	public void close() throws IOException {
		this.s.close();
	}
	
}
