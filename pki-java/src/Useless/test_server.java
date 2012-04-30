package Useless;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;


public class test_server {
	
	public static void main(String[] args) throws IOException, ClassNotFoundException {
		String message = "";
		/*ServerSocketChannel s = ServerSocketChannel.open();
		s.socket().bind(new InetSocketAddress(5555));
		SocketChannel s_cli = s.accept();
		ByteBuffer buf = ByteBuffer.allocate(4096);
		s_cli.read(buf);
		buf.flip();
		while(buf.hasRemaining())
			message += (char)buf.get();*/
		
		ServerSocket serv_s = new ServerSocket(5555);
		Socket s = serv_s.accept();
		ObjectInputStream stream = new ObjectInputStream(s.getInputStream());
		X509Certificate c = (X509Certificate) stream.readObject();
		
		System.out.println(c.toString());
	}
}
