package com.upm.eui.tfc.scp.utiles;

/**
 * Clase que encapsula una excepcion generada por un problema criptografico.
 * 
 * @version 1.0
 */

public class CryptoException extends Exception {

	private static final long serialVersionUID = 1L;

	public CryptoException() {
		super();
	}

	public CryptoException(String sMessage) {
		super(sMessage);
	}

	public CryptoException(String sMessage, Throwable causeThrowable) {
		super(sMessage, causeThrowable);
	}

	public CryptoException(Throwable causeThrowable) {
		super(causeThrowable);
	}
}
