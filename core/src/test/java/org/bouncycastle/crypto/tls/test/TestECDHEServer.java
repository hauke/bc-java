package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.DTLSServerProtocol;
import org.bouncycastle.crypto.tls.DTLSTransport;
import org.bouncycastle.crypto.tls.DatagramTransport;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TLSCertificateTye;
import org.bouncycastle.crypto.tls.UDPTransport;

public class TestECDHEServer {

	static class MyTlsServer extends DefaultTlsServer {

		@Override
		public int[] getCipherSuites() {
			int[] ciphersOrig = super.getCipherSuites();
			int[] ciphers = Arrays.copyOf(ciphersOrig, ciphersOrig.length + 1);
			ciphers[ciphersOrig.length] = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
			return ciphers;
		}

		@Override
		public void notifySecureRenegotiation(boolean secureRenegotiation)
				throws IOException {
		}

		@Override
		public short[] getServerCertificateFormats() throws IOException {
			return new short[] { TLSCertificateTye.X509, TLSCertificateTye.Raw };
		}

		@Override
		public short[] getClientCertificateFormats() throws IOException {
			return new short[] { TLSCertificateTye.X509, TLSCertificateTye.Raw };
		}

		@Override
		public ProtocolVersion getServerVersion() {
			return ProtocolVersion.DTLSv12;
		}

		@Override
		public ProtocolVersion getMinimumVersion() {
			return ProtocolVersion.DTLSv10;
		}

	}

	public static void main(String[] args) throws Exception {
		SecureRandom secureRandom = new SecureRandom();
		DTLSServerProtocol serverProtocol = new DTLSServerProtocol(secureRandom);

		DatagramSocket socket = new DatagramSocket(new InetSocketAddress(20220));
		socket.receive(p);
		socket.re
		int mtu = 1500;
		DatagramTransport transport = new UDPTransport(socket, mtu);
		ServerThread serverThread = new ServerThread(serverProtocol, transport);
		serverThread.start();
	}

	static class ServerThread extends Thread {
		private final DTLSServerProtocol serverProtocol;
		private final DatagramTransport serverTransport;
		private volatile boolean isShutdown = false;

		ServerThread(DTLSServerProtocol serverProtocol,
				DatagramTransport serverTransport) {
			this.serverProtocol = serverProtocol;
			this.serverTransport = serverTransport;
		}

		public void run() {
			try {

				MyTlsServer server = new MyTlsServer();
				DTLSTransport dtlsServer = serverProtocol.accept(server,
						serverTransport);
				byte[] buf = new byte[dtlsServer.getReceiveLimit()];
				while (!isShutdown) {
					int length = dtlsServer.receive(buf, 0, buf.length, 1000);
					if (length >= 0) {
						dtlsServer.send(buf, 0, length);
					}
				}
				dtlsServer.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		void shutdown() throws InterruptedException {
			if (!isShutdown) {
				isShutdown = true;
				this.join();
			}
		}
	}
}
