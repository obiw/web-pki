package com.upm.eui.tfc.scp.manager;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Date;

import javax.swing.JTextArea;

/**
 * Clase encargada de gestionar la impresion de los mensajes en los ficheros de
 * logs de la aplicacion. Ofrece a la aplicacion tres niveles de log (AVISO,
 * INFORMACION, ERROR) y gestiona la salida tanto en fichero como en la consola
 * de administracion.
 * 
 * @version 1.0
 */

public class LogManager {

	private JTextArea log;
	private File f;
	private FileOutputStream fos = null;

	public LogManager(JTextArea jta, File file) {
		this.log = jta;
		this.f = file;
	}

	public void log(String peticion, int tipo) {
		try {
			fos = new FileOutputStream(f, true);
			switch (tipo) {
			case 0:
				log.setText("INFORMACION - " + new Date() + " - " + peticion
						+ "\n" + log.getText());
				fos.write(("INFORMACION - " + new Date() + " - " + peticion
						+ "\n" + log.getText()).getBytes());
				break;
			case 1:
				log.setText("AVISO - " + new Date() + " - " + peticion + "\n"
						+ log.getText());
				fos
						.write(("AVISO - " + new Date() + " - " + peticion
								+ "\n" + log.getText()).getBytes());
				break;
			case 2:
				log.setText("ERROR - " + new Date() + " - " + peticion + "\n"
						+ log.getText());
				fos
						.write(("ERROR - " + new Date() + " - " + peticion
								+ "\n" + log.getText()).getBytes());
				break;
			}
			fos.close();
		} catch (Exception ex) {
			log
					.append("ERROR - " + new Date() + " - " + ex.getMessage()
							+ "\n");
		}
	}

}
