package Playground;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;


public class client_test {
	
	public static void main(String[] args) throws IOException {
		SocketChannel s = SocketChannel.open();
		//s.configureBlocking(false); //pas obligatoire
		s.connect(new InetSocketAddress("localhost",5555));

		String message = "Coucou";
		String message2 = "Tu veux voir";
		String message3 = "Ma Bite !";
		
		s.write(ByteBuffer.wrap(message.getBytes()));
		
		s.close();
	}
}
