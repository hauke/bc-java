package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * Parsing and encoding of a <i>Certificate</i> struct from RFC 4346.
 * <p/>
 * <pre>
 * opaque ASN.1Cert<2^24-1>;
 *
 * struct {
 *     ASN.1Cert certificate_list<0..2^24-1>;
 * } Certificate;
 * </pre>
 *
 * @see org.bouncycastle.asn1.x509.Certificate
 */
public class CertificateRaw implements Certificate
{
    protected org.bouncycastle.asn1.x509.SubjectPublicKeyInfo pubKey;

    public CertificateRaw(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo pubKey)
    {
        if (pubKey == null)
        {
            throw new IllegalArgumentException("'Public key' cannot be null");
        }

        this.pubKey = pubKey;
    }

    
	public SubjectPublicKeyInfo getFirstSubjectPublicKeyInfo() {
		return pubKey;
	}

    public int getLength()
    {
    	return 1;
    }
    
    /**
     * @return <code>true</code> if this certificate chain contains no certificates, or
     *         <code>false</code> otherwise.
     */
    public boolean isEmpty()
    {
    	return pubKey != null;
    }

    /**
     * Encode this {@link CertificateRaw} to an {@link OutputStream}.
     *
     * @param output the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output)
        throws IOException
    {
        byte[] derEncoding = pubKey.getEncoded(ASN1Encoding.DER);
        TlsUtils.writeOpaque24(derEncoding, output);
    }
    
    /**
     * Parse a {@link CertificateRaw} from an {@link InputStream}.
     *
     * @param input the {@link InputStream} to parse from.
     * @return a {@link CertificateRaw} object.
     * @throws IOException
     */
    public static CertificateRaw parse(InputStream input)
        throws IOException
    {
        int totalLength = TlsUtils.readUint24(input);
        if (totalLength == 0)
        {
            return null;
        }

        int length = TlsUtils.readUint24(input);
        if (length + 3 != totalLength) {
        	return null;
        }
        byte[] pubKey = TlsUtils.readFully(length, input);

        ASN1Primitive asn1PubKey = TlsUtils.readDERObject(pubKey);
        return new CertificateRaw(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(asn1PubKey));
    }
}
