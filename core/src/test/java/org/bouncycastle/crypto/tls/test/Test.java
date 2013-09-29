package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.DTLSClientProtocol;
import org.bouncycastle.crypto.tls.DTLSTransport;
import org.bouncycastle.crypto.tls.DatagramTransport;
import org.bouncycastle.crypto.tls.PSKTlsClient;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsCipherFactory;
import org.bouncycastle.crypto.tls.TlsPSKIdentity;
import org.bouncycastle.crypto.tls.UDPTransport;

public class Test {

	public static class MyTlsPSKIdentity implements TlsPSKIdentity {

		public void skipIdentityHint() {
			// TODO Auto-generated method stub

		}

		public void notifyIdentityHint(byte[] psk_identity_hint) {
			// TODO Auto-generated method stub

		}

		public byte[] getPSKIdentity() {
			return "Client_identity".getBytes();
		}

		public byte[] getPSK() {
			return "secretPSK".getBytes();
		}

	}

	public static class MyPSKTlsClient extends PSKTlsClient {

		public MyPSKTlsClient(TlsPSKIdentity pskIdentity) {
			super(pskIdentity);
		}

		@Override
		public int[] getCipherSuites() {
			int[] ciphersOrig = super.getCipherSuites();
			int[] ciphers = Arrays.copyOf(ciphersOrig, ciphersOrig.length + 1);
			ciphers[ciphersOrig.length] = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
			return ciphers;
		}

		public MyPSKTlsClient(TlsCipherFactory cipherFactory,
				TlsPSKIdentity pskIdentity) {
			super(cipherFactory, pskIdentity);
		}

		public TlsAuthentication getAuthentication() throws IOException {
			return new ServerOnlyTlsAuthentication() {

				public void notifyServerCertificate(
						Certificate serverCertificate) throws IOException {

				}
			};
		}
		@Override
		public void notifySecureRenegotiation(boolean secureRenegotiation)
				throws IOException {

		}

		@Override
		public ProtocolVersion getClientVersion() {
			return ProtocolVersion.DTLSv12;
		}

		@Override
		public ProtocolVersion getMinimumVersion() {
			return ProtocolVersion.DTLSv10;
		}

	}

	private static final SecureRandom secureRandom = new SecureRandom();

	public static void main(String[] args) throws Exception {
		DatagramSocket socket = new DatagramSocket();

		MyTlsPSKIdentity identity = new MyTlsPSKIdentity();
		MyPSKTlsClient client = new MyPSKTlsClient(identity);
		DTLSClientProtocol protocol = new DTLSClientProtocol(secureRandom);

		socket.connect(InetAddress.getByName("localhost"), 20220);
		int mtu = 1500;
		DatagramTransport transport = new UDPTransport(socket, mtu);

		DTLSTransport dtls = protocol.connect(client, transport);
		byte[] buf = "Hallo".getBytes();
		dtls.send(buf, 0, buf.length);
		byte[] result = new byte[200];
		dtls.receive(result, 0, result.length, 5000);
		System.out.println(new String(result));
		dtls.close();
		transport.close();
		socket.close();
	}
}
