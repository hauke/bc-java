package org.bouncycastle.crypto.tls.test;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class UDPTestClient {
	public static void main(String[] args) throws Exception {
		DatagramSocket socket = new DatagramSocket();
		byte[] buf = "Hallo".getBytes();
		socket.connect(InetAddress.getByName("localhost"), 12345);
		


		DatagramPacket packet = new DatagramPacket(buf, buf.length);
		socket.send(packet);
		
		packet = new DatagramPacket(buf, buf.length);
		  socket.setSoTimeout(10000);
		socket.receive(packet);
		String received = new String(packet.getData(), 0, packet.getLength());
		System.out.println("Quote of the Moment: " + received);
	}
}
