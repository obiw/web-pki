package com.upm.eui.tfc.scp.excep;

/**
 * Clase de la excepcion de la autoridad certificador. Cualquier error que
 * encuentre la CA al realizar cualquiera de sus operaciones generara una
 * CAManagerException con un texto descriptivo del erro.
 * 
 * @version 1.0
 */

public class CAManagerException extends Exception {

	private static final long serialVersionUID = 1L;
	private String message;

	public CAManagerException() {
		super();
	}

	public CAManagerException(String sMessage) {
		message = sMessage;
	}

	public String getMessage() {
		return message;
	}

}
