package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.OutputStream;

public interface Certificate {
	int getLength();

	boolean isEmpty();

	void encode(OutputStream output)  throws IOException;
	
	org.bouncycastle.asn1.x509.SubjectPublicKeyInfo getFirstSubjectPublicKeyInfo();
}
