package com.upm.eui.tfc.scp.utiles;

import java.io.InvalidObjectException;
import java.io.ObjectStreamException;
import java.text.MessageFormat;

/**
 * Clase que encapsula distintos metodos y procedimientos utiles para el manejo
 * de claves asimetricas.
 * 
 * @version 1.0
 */

public class KeyPairType extends Object {

	private final String m_sType;

	private static final String RSA_STR = "RSA";

	private static final String DSA_STR = "DSA";

	public static final KeyPairType RSA = new KeyPairType(RSA_STR);

	public static final KeyPairType DSA = new KeyPairType(DSA_STR);

	private KeyPairType(String sType) {
		m_sType = sType;
	}

	private Object readResolve() throws ObjectStreamException {
		if (m_sType.equals(RSA_STR)) {
			return RSA;
		} else if (m_sType.equals(DSA_STR)) {
			return DSA;
		} else {
			throw new InvalidObjectException(MessageFormat.format(
					"NoResolveKeypairtype.exception.message",
					new Object[] { m_sType }));
		}
	}

	public String toString() {
		return m_sType;
	}
}
