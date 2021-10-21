package com.upm.eui.tfc.scp.utiles;

import java.io.InvalidObjectException;
import java.io.ObjectStreamException;
import java.text.MessageFormat;

/**
 * Clase que encapsula distintos metodos y procedimientos utiles para el manejo
 * de firmas digitales.
 * 
 * @version 1.0
 */

public class SignatureType extends Object {

	private final String m_sType;

	private static final String RSA_MD2_STR = "MD2withRSA";

	private static final String RSA_MD5_STR = "MD5withRSA";

	private static final String RSA_SHA1_STR = "SHA1withRSA";

	private static final String DSA_SHA1_STR = "SHA1withDSA";

	public static final SignatureType RSA_MD2 = new SignatureType(RSA_MD2_STR);

	public static final SignatureType RSA_MD5 = new SignatureType(RSA_MD5_STR);

	public static final SignatureType RSA_SHA1 = new SignatureType(RSA_SHA1_STR);

	public static final SignatureType DSA_SHA1 = new SignatureType(DSA_SHA1_STR);

	private SignatureType(String sType) {
		m_sType = sType;
	}

	private Object readResolve() throws ObjectStreamException {
		if (m_sType.equals(RSA_MD2_STR)) {
			return RSA_MD2;
		} else if (m_sType.equals(RSA_MD5_STR)) {
			return RSA_MD5;
		} else if (m_sType.equals(RSA_SHA1_STR)) {
			return RSA_SHA1;
		} else if (m_sType.equals(DSA_SHA1_STR)) {
			return DSA_SHA1;
		} else {
			throw new InvalidObjectException(MessageFormat.format(
					"NoResolveSignaturetype.exception.message",
					new Object[] { m_sType }));
		}
	}

	public String toString() {
		return m_sType;
	}
}
