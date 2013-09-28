package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class UDPTestServer {
	public static void main(String[] args) throws Exception {
		DatagramSocket socket = null;
		try {
			socket = new DatagramSocket(12345, InetAddress.getByName("localhost"));

			while (true) {
				try {
					byte[] buf = new byte[1000];
					DatagramPacket pack = new DatagramPacket(buf, buf.length);
					socket.receive(pack);
					System.out.println("length: " + pack.getLength());
					Thread.sleep(8 * 1000);

					byte[] sendBuf = Integer.toString(pack.getLength())
							.getBytes();

					DatagramPacket sendPack = new DatagramPacket(sendBuf,
							sendBuf.length, pack.getAddress(), pack.getPort());

					socket.send(sendPack);
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		} finally {
			if (socket != null) {
				socket.close();
			}
		}
	}
}
