package Playground;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;


public class test_server {
	
	public static void main(String[] args) throws IOException {
		String message = null;
		
		ServerSocketChannel s = ServerSocketChannel.open();
		s.socket().bind(new InetSocketAddress(5555));
		SocketChannel s_cli = s.accept();
		
		ByteBuffer buf = ByteBuffer.allocate(4096);
		s_cli.read(buf);
		
		buf.flip();
		while(buf.hasRemaining()) {
			System.out.println((char)buf.get());
		}	
	}
}
