package com.upm.eui.tfc.scp.utiles;

import java.io.InvalidObjectException;
import java.io.ObjectStreamException;
import java.text.MessageFormat;

/**
 * Clase que encapsula distintos metodos y procedimientos utiles para el manejo
 * de algoritmos de resumenes.
 * 
 * @version 1.0
 */

public class DigestType extends Object {

	private final String m_sType;

	private static final String MD5_STR = "MD5";

	private static final String SHA1_STR = "SHA1";

	public static final DigestType MD5 = new DigestType(MD5_STR);

	public static final DigestType SHA1 = new DigestType(SHA1_STR);

	private DigestType(String sType) {
		m_sType = sType;
	}

	private Object readResolve() throws ObjectStreamException {
		if (m_sType.equals(MD5_STR)) {
			return MD5;
		} else if (m_sType.equals(SHA1_STR)) {
			return SHA1;
		} else {
			throw new InvalidObjectException(MessageFormat.format(
					"NoResolveDigesttype.exception.message",
					new Object[] { m_sType }));
		}
	}

	public String toString() {
		return m_sType;
	}
}
