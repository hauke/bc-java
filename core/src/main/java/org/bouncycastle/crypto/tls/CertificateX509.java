package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

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
public class CertificateX509 implements Certificate
{
    public static final CertificateX509 EMPTY_CHAIN = new CertificateX509(
        new org.bouncycastle.asn1.x509.Certificate[0]);

    protected org.bouncycastle.asn1.x509.Certificate[] certificateList;

    public CertificateX509(org.bouncycastle.asn1.x509.Certificate[] certificateList)
    {
        if (certificateList == null)
        {
            throw new IllegalArgumentException("'certificateList' cannot be null");
        }

        this.certificateList = certificateList;
    }

    /**
     * @deprecated use {@link #getCertificateList()} instead
     */
    public org.bouncycastle.asn1.x509.Certificate[] getCerts()
    {
        return getCertificateList();
    }

    /**
     * @return an array of {@link org.bouncycastle.asn1.x509.Certificate} representing a certificate
     *         chain.
     */
    public org.bouncycastle.asn1.x509.Certificate[] getCertificateList()
    {
        return cloneCertificateList();
    }

    public org.bouncycastle.asn1.x509.Certificate getCertificateAt(int index)
    {
        return certificateList[index];
    }

	public SubjectPublicKeyInfo getFirstSubjectPublicKeyInfo() {
		if (certificateList.length == 0){
		    return null;
		}
		return certificateList[0].getSubjectPublicKeyInfo();
	}
    
    public int getLength()
    {
        return certificateList.length;
    }

    /**
     * @return <code>true</code> if this certificate chain contains no certificates, or
     *         <code>false</code> otherwise.
     */
    public boolean isEmpty()
    {
    	return certificateList.length == 0;
    }

    /**
     * Encode this {@link CertificateX509} to an {@link OutputStream}.
     *
     * @param output the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output)
        throws IOException
    {
        Vector derEncodings = new Vector(this.certificateList.length);

        int totalLength = 0;
        for (int i = 0; i < this.certificateList.length; ++i)
        {
            byte[] derEncoding = certificateList[i].getEncoded(ASN1Encoding.DER);
            derEncodings.addElement(derEncoding);
            totalLength += derEncoding.length + 3;
        }

        TlsUtils.checkUint24(totalLength);
        TlsUtils.writeUint24(totalLength, output);

        for (int i = 0; i < derEncodings.size(); ++i)
        {
            byte[] derEncoding = (byte[])derEncodings.elementAt(i);
            TlsUtils.writeOpaque24(derEncoding, output);
        }
    }

    /**
     * Parse a {@link CertificateX509} from an {@link InputStream}.
     *
     * @param input the {@link InputStream} to parse from.
     * @return a {@link CertificateX509} object.
     * @throws IOException
     */
    public static CertificateX509 parse(InputStream input)
        throws IOException
    {
        int totalLength = TlsUtils.readUint24(input);
        if (totalLength == 0)
        {
            return EMPTY_CHAIN;
        }

        byte[] certListData = TlsUtils.readFully(totalLength, input);

        ByteArrayInputStream buf = new ByteArrayInputStream(certListData);

        Vector certificate_list = new Vector();
        while (buf.available() > 0)
        {
            byte[] derEncoding = TlsUtils.readOpaque24(buf);
            ASN1Primitive asn1Cert = TlsUtils.readDERObject(derEncoding);
            certificate_list.addElement(org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert));
        }

        org.bouncycastle.asn1.x509.Certificate[] certificateList = new org.bouncycastle.asn1.x509.Certificate[certificate_list.size()];
        for (int i = 0; i < certificate_list.size(); i++)
        {
            certificateList[i] = (org.bouncycastle.asn1.x509.Certificate)certificate_list.elementAt(i);
        }
        return new CertificateX509(certificateList);
    }

    protected org.bouncycastle.asn1.x509.Certificate[] cloneCertificateList()
    {
    	if (certificateList == null) {
    	  return null;
    	}
        org.bouncycastle.asn1.x509.Certificate[] result = new org.bouncycastle.asn1.x509.Certificate[certificateList.length];
        System.arraycopy(certificateList, 0, result, 0, result.length);
        return result;
    }
}
