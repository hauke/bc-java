package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Stack;
import java.util.concurrent.Semaphore;

import org.bouncycastle.crypto.tls.DatagramTransport;

public class UDPServer {

	public static class UDPServerConnection implements DatagramTransport {
		private final InetAddress addr;

		public UDPServerConnection(InetAddress addr) {
			this.addr = addr;
		}

		public void receive(DatagramPacket p) {
			// TODO Auto-generated method stub
		}

		public int getReceiveLimit() throws IOException {
			// TODO Auto-generated method stub
			return 0;
		}

		public int getSendLimit() throws IOException {
			// TODO Auto-generated method stub
			return 0;
		}

		public int receive(byte[] buf, int off, int len, int waitMillis)
				throws IOException {
			// TODO Auto-generated method stub
			return 0;
		}

		public void send(byte[] buf, int off, int len) throws IOException {
			// TODO Auto-generated method stub
			
		}

		public void close() throws IOException {
			// TODO Auto-generated method stub
			
		}

	}

	private DatagramSocket socket;
	private Map<InetAddress, UDPServerConnection> listener = new HashMap<InetAddress, UDPServerConnection>();

	private Stack<UDPServerConnection> newWaiting = new Stack<UDPServerConnection>();

	private Semaphore newWaitLock = new Semaphore(0);

	public UDPServer(DatagramSocket socket) {
		this.socket = socket;
	}

	public UDPServerConnection accept() {
		try {
			newWaitLock.acquire();
		} catch (InterruptedException e) {
			return null;
		}
		return newWaiting.pop();
	}

	public void start() throws IOException {
		byte[] buf = new byte[1512];
		DatagramPacket p = new DatagramPacket(buf, buf.length);
		socket.receive(p);
		InetAddress addr = p.getAddress();
		UDPServerConnection con = listener.get(addr);
		if (con == null) {
			con = new UDPServerConnection(addr);
			listener.put(addr, con);
			newWaiting.add(con);
			newWaitLock.release();
		}
		con.receive(p);
	}

	public static void main(String[] args) throws Exception {

	}
}
