package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x509.Certificate;

import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class TlsProtocolTest
    extends TestCase
{
    public void testClientServer()
        throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();

        PipedInputStream clientRead = new PipedInputStream();
        PipedInputStream serverRead = new PipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite, secureRandom);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite, secureRandom);

        ServerThread serverThread = new ServerThread(serverProtocol);
        serverThread.start();

        MockTlsClient client = new MockTlsClient(null);
        clientProtocol.connect(client);

        // NOTE: Because we write-all before we read-any, this length can't be more than the pipe capacity
        int length = 1000;

        byte[] data = new byte[length];
        secureRandom.nextBytes(data);

        OutputStream output = clientProtocol.getOutputStream();
        output.write(data);

        byte[] echo = new byte[data.length];
        int count = Streams.readFully(clientProtocol.getInputStream(), echo);

        assertEquals(count, data.length);
        assertTrue(Arrays.areEqual(data, echo));

        output.close();

        serverThread.join();
    }

    static class ServerThread
        extends Thread
    {
        private final TlsServerProtocol serverProtocol;

        ServerThread(TlsServerProtocol serverProtocol)
        {
            this.serverProtocol = serverProtocol;
        }

        public void run()
        {
            try
            {
                MockTlsServer server = new MockTlsServer();
                serverProtocol.accept(server);
                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (Exception e)
            {
//                throw new RuntimeException(e);
            }
            if (cause != null)
            {
                cause.printStackTrace(out);
            }
        }

        public void notifyAlertReceived(short alertLevel, short alertDescription)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS server received alert (AlertLevel." + alertLevel + ", AlertDescription."
                + alertDescription + ")");
        }

        public CertificateRequest getCertificateRequest()
        {
            return new CertificateRequest(new short[]{ ClientCertificateType.rsa_sign }, null, null);
        }

        public void notifyClientCertificate(org.bouncycastle.crypto.tls.CertificateX509 clientCertificate)
            throws IOException
        {
            Certificate[] chain = clientCertificate.getCertificateList();
            System.out.println("Received client certificate chain of length " + chain.length);
            for (int i = 0; i != chain.length; i++)
            {
                Certificate entry = chain[i];
                // TODO Create fingerprint based on certificate signature algorithm digest
                System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                    + entry.getSubject() + ")");
            }
        }

        protected TlsEncryptionCredentials getRSAEncryptionCredentials()
            throws IOException
        {
            return TlsTestUtils.loadEncryptionCredentials(context, new String[]{"x509-server.pem", "x509-ca.pem"},
                "x509-server-key.pem");
        }

        protected TlsSignerCredentials getRSASignerCredentials()
            throws IOException
        {
            return TlsTestUtils.loadSignerCredentials(context, new String[]{"x509-server.pem", "x509-ca.pem"},
                "x509-server-key.pem");
        }
    }
}
