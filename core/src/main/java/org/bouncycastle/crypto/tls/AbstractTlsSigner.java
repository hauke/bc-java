package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public abstract class AbstractTlsSigner
    implements TlsSigner
{
    protected TlsContext context;

    public void init(TlsContext context)
    {
        this.context = context;
    }

    public byte[] generateRawSignature(AsymmetricKeyParameter privateKey, byte[] md5AndSha1)
        throws CryptoException
    {
        if(TlsUtils.isTLSv12(context))
        {
            SignatureAndHashAlgorithm algo = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
            return generateRawSignature(algo, privateKey, md5AndSha1);    
        } 
        return generateRawSignature(null, privateKey, md5AndSha1);
    }

    public boolean verifyRawSignature(byte[] sigBytes, AsymmetricKeyParameter publicKey, byte[] md5AndSha1)
        throws CryptoException
    {
        return verifyRawSignature(null, sigBytes, publicKey, md5AndSha1);
    }

    public Signer createSigner(AsymmetricKeyParameter privateKey)
    {
        return createSigner(null, privateKey);
    }

    public Signer createVerifyer(AsymmetricKeyParameter publicKey)
    {
        return createVerifyer(null, publicKey);
    }
}
