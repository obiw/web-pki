package com.upm.eui.tfc.scp.http;

/**
 * Clase encargada de levantar el interfaz web de la aplicacion para HTTP. Obtendra del gestor de configuracion los distintos
 * parametros como puerto o directorio raiz de las paginas web. Gestionara la recepcion y el envio de peticiones. Utilizara
 * la clase HttpClient para el procesamiento de las peticiones asi como para la generacion de las respuestas.
 * 
 * @version 1.0
 */

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import org.jdom.JDOMException;

import com.upm.eui.tfc.scp.excep.CAManagerException;
import com.upm.eui.tfc.scp.manager.ConfigManager;
import com.upm.eui.tfc.scp.manager.LogManager;
import com.upm.eui.tfc.scp.manager.RAManager;

public class HttpServer extends Thread {

	protected char[] storePassword;
	protected char[] keyPassword;
	private LogManager logger;
	private ServerSocket ss = null;
	private String webroot;
	private String index;
	private int puerto;
	private RAManager ramanager = null;

	public HttpServer(String pass1, String pass2, LogManager log, RAManager ra)
			throws Exception {
		this.storePassword = pass1.toCharArray();
		this.keyPassword = pass2.toCharArray();
		this.webroot = ConfigManager.obtenerParametro("INSTALACION/DIRECTORIO")
				+ "/html";
		this.index = ConfigManager.obtenerParametro("SERVIDOR/INDEX");
		this.puerto = Integer.parseInt(ConfigManager
				.obtenerParametro("SERVIDOR/PUERTO"));
		this.logger = log;
		this.ramanager = ra;
		this.start();
	}

	public void run() {
		try {
			ss = new ServerSocket(puerto);
		} catch (IOException ex) {
			logger.log("Excepcion: " + ex.getMessage(), 2);
		}

		if (ss != null) {
			try {
				logger.log("Servidor HTTP levantado en el puerto; "
						+ ConfigManager.obtenerParametro("SERVIDOR/PUERTO"), 0);
				while (true) {
					Socket s = ss.accept();
					new HttpClient(s, storePassword, keyPassword, webroot,
							index, logger, ramanager);
				}
			} catch (JDOMException ex) {
				logger.log(ex.getMessage(), 2);
			} catch (CAManagerException ex) {
				logger.log(ex.getMessage(), 2);
			} catch (IOException ex) {
				logger.log(ex.getMessage(), 2);
			}

		} else {
			logger.log(
					"No se pudo arrancar el servidor, ocurrio una exception.",
					1);
		}
	}

	public void detener() throws IOException {
		this.ss.close();
		logger.log("Servidor HTTP detenido.", 0);
	}

}
