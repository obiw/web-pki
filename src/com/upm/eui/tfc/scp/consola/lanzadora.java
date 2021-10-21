package com.upm.eui.tfc.scp.consola;

import com.upm.eui.tfc.scp.manager.ConfigManager;

/**
 * Clase main de la aplicacion. Ejecutando esta clase como una aplicacion java
 * se levanta el sistema. Es la clase encargada de comprobar si la Autoridad
 * Certificadora esta inicializada o no para arrancar, en funcion de ello, una
 * GUI u otra.
 * 
 * @version 1.0
 */

public class lanzadora {

	public static void main(String[] args) {

		try {

			java.security.Provider provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
			java.security.Security.addProvider(provider);

			if (ConfigManager.obtenerParametro("CA/INICIALIZADA")
					.compareToIgnoreCase("N") == 0) {
				inicializarCA.iniciar();
			} else {
				arrancar();
			}

		} catch (Exception ex) {
			ex.printStackTrace();
		}

	}

	private static void arrancar() {
		consolaCA.inicializar();
	}
}
