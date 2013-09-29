package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.DTLSClientProtocol;
import org.bouncycastle.crypto.tls.DTLSTransport;
import org.bouncycastle.crypto.tls.DatagramTransport;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TLSCertificateTye;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClientContext;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.UDPTransport;

public class TestECDHE {

    public static class MyTlsAuthentication implements TlsAuthentication {

        private TlsClientContext context;

        public MyTlsAuthentication(TlsClientContext context) {
            this.context = context;
        }

        public void notifyServerCertificate(Certificate serverCertificate) throws IOException
        {
            System.out.println(serverCertificate.getFirstSubjectPublicKeyInfo());
        }

        public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                throws IOException
        {

            short[] certificateTypes = certificateRequest.getCertificateTypes();
System.out.println("certificateTypes: "+ certificateTypes);
                        // TODO Create a distinct client certificate for use here
                        return TlsTestUtils.loadRawSignerCredentials(context, 
                                "x509-server.pem", "x509-server-key.pem");
        }

    };

    public static class MyTlsClient extends DefaultTlsClient {

        @Override
        public int[] getCipherSuites()
        {
            int[] ciphersOrig = super.getCipherSuites();
            int[] ciphers = Arrays.copyOf(ciphersOrig, ciphersOrig.length + 1);
            ciphers[ciphersOrig.length] = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
            return ciphers;
        }

        public TlsAuthentication getAuthentication() throws IOException
        {
            return new MyTlsAuthentication(context);
        }

        @Override
        public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException
        {
        }

        @Override
        public short[] getServerCertificateFormats() throws IOException
        {
            return new short[] { TLSCertificateTye.X509, TLSCertificateTye.Raw };
        }

        @Override
        public short[] getClientCertificateFormats() throws IOException
        {
            return new short[] { TLSCertificateTye.X509, TLSCertificateTye.Raw };
        }

        @Override
        public ProtocolVersion getClientVersion()
        {
            return ProtocolVersion.DTLSv12;
        }

        @Override
        public ProtocolVersion getMinimumVersion()
        {
            return ProtocolVersion.DTLSv10;
        }

    }

    private static final SecureRandom secureRandom = new SecureRandom();

    public static void main(String[] args) throws Exception
    {
        DatagramSocket socket = new DatagramSocket();

        MyTlsClient client = new MyTlsClient();
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
