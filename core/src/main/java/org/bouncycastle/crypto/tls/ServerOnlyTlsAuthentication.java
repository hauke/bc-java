package org.bouncycastle.crypto.tls;


public abstract class ServerOnlyTlsAuthentication
    implements TlsAuthentication
{
    public final TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
    {
        return null;
    }

    public short[] getSupportedClientCredentialFormats() {
        return new short[]{TLSCertificateTye.X509 };
    }

    public short[] getSupportedServerCredentialFormats() {
        return new short[]{TLSCertificateTye.X509 };
    }
}
