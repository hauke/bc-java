package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface TlsCertificate {
    void generateClientCertificate(OutputStream output)
            throws IOException;

        void processClientCertificate(InputStream input)
            throws IOException;
        
        void generateServerCertificate(OutputStream output)
                throws IOException;

            void processServerCertificate(InputStream input)
                throws IOException;

			void init(TlsClientContextImpl clientContext);
}
