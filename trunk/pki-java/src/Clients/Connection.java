package Clients;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.UnknownHostException;

public abstract class Connection {
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
			this.out = new DataOutputStream(s.getOutputStream()); //A noter que j'utilise des DataOutputStream et pas des ObjectOutputStream
			this.in = new DataInputStream(s.getInputStream());
	}
	
	public boolean connectionOK() {
		return this.finishedOK = true;
	}
	
	public abstract void run();
	
	public boolean finishedWell() {
		return finishedOK;
	}
	
	public String getErrorMessage() {
		return this.errormessage;
	}
	
	public byte[] read() throws IOException {
		byte[] res = new byte[4096]; //Créer un tableau très grand. (Je m'attends a tout recevoir d'un coup j'ai pas envie de me faire chier)
		int read = this.in.read(res); //Je lis
		if (read == -1) { //si on a rien lu c'est que le serveur a eu un problème
				throw new IOException();
		}
		
		byte[] res_fitted = new byte[read]; //je déclare un tableau de la taille juste
		for (int i=0; i < read; i++) { //je recopie le byte dedans
			res_fitted[i] = res[i];
		}
		return res_fitted;
	}
	
	public void close() throws IOException {
		this.s.close();
	}
	
}
