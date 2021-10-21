package com.upm.eui.tfc.scp.utiles;

import java.io.InvalidObjectException;
import java.io.ObjectStreamException;
import java.text.MessageFormat;

/**
 * Clase que encapsula distintos metodos y procedimientos utiles para el manejo
 * de almacenes de certificados digitales.
 * 
 * @version 1.0
 */

public class KeyStoreType extends Object {

	private final String m_sType;

	private static final String JCEKS_STR = "JCEKS";

	private static final String JKS_STR = "JKS";

	private static final String PKCS12_STR = "PKCS12";

	private static final String BKS_STR = "BKS";

	private static final String UBER_STR = "UBER";

	public static final KeyStoreType JCEKS = new KeyStoreType(JCEKS_STR);

	public static final KeyStoreType JKS = new KeyStoreType(JKS_STR);

	public static final KeyStoreType PKCS12 = new KeyStoreType(PKCS12_STR);

	public static final KeyStoreType BKS = new KeyStoreType(BKS_STR);

	public static final KeyStoreType UBER = new KeyStoreType(UBER_STR);

	private KeyStoreType(String sType) {
		m_sType = sType;
	}

	private Object readResolve() throws ObjectStreamException {
		if (m_sType.equals(JCEKS_STR)) {
			return JCEKS;
		} else if (m_sType.equals(JKS_STR)) {
			return JKS;
		} else if (m_sType.equals(PKCS12_STR)) {
			return PKCS12;
		} else if (m_sType.equals(BKS_STR)) {
			return BKS;
		} else if (m_sType.equals(UBER_STR)) {
			return UBER;
		} else {
			throw new InvalidObjectException(MessageFormat.format(
					"NoResolveKeystoretype.exception.message",
					new Object[] { m_sType }));
		}
	}

	public String toString() {
		return m_sType;
	}
}
