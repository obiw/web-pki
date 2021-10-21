package com.upm.eui.tfc.scp.http;

/**
 * Clase encargada de levantar el interfaz web de la aplicacion para HTTPS. Obtendra del gestor de configuracion los distintos
 * parametros como puerto, el directorio raiz de las paginas web o el certificado de servidor seguro. Gestionara la recepcion y el envio de peticiones. Utilizara
 * la clase HttpClient para el procesamiento de las peticiones asi como para la generacion de las respuestas.
 * 
 * @version 1.0
 */

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import org.jdom.JDOMException;

import com.upm.eui.tfc.scp.excep.CAManagerException;
import com.upm.eui.tfc.scp.manager.ConfigManager;
import com.upm.eui.tfc.scp.manager.LogManager;
import com.upm.eui.tfc.scp.manager.RAManager;

public class HttpsServer extends Thread {

	protected char[] storePassword;
	protected char[] keyPassword;
	private LogManager logger;
	private ServerSocket ss = null;
	private String webroot;
	private String index;
	private int puerto;
	private RAManager ramanager = null;

	String keystore = "";

	public HttpsServer(String pass1, String pass2, LogManager log, RAManager ra)
			throws Exception {
		this.storePassword = pass1.toCharArray();
		this.keyPassword = pass2.toCharArray();
		this.webroot = ConfigManager.obtenerParametro("INSTALACION/DIRECTORIO")
				+ "/html";
		this.index = ConfigManager.obtenerParametro("SERVIDOR/INDEX");
		this.puerto = Integer.parseInt(ConfigManager
				.obtenerParametro("SERVIDOR/SSL/PUERTO"));
		this.keystore = ConfigManager
				.obtenerParametro("INSTALACION/DIRECTORIO")
				+ "/certs/ssl.ks";
		this.logger = log;
		this.ramanager = ra;
		this.start();
	}

	public ServerSocket getServer() throws Exception {

		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(new FileInputStream(keystore), storePassword);
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(ks, keyPassword);
		SSLContext sslcontext = SSLContext.getInstance("SSLv3");
		sslcontext.init(kmf.getKeyManagers(), null, null);
		ServerSocketFactory ssf = sslcontext.getServerSocketFactory();
		SSLServerSocket serversocket = (SSLServerSocket) ssf
				.createServerSocket(this.puerto);
		return serversocket;

	}

	public void run() {

		try {
			ss = getServer();
		} catch (Exception ex) {
			logger.log(ex.getMessage(), 2);
		}

		if (ss != null) {
			try {
				logger
						.log(
								"Servidor HTTPS levantado en el puerto; "
										+ ConfigManager
												.obtenerParametro("SERVIDOR/SSL/PUERTO"),
								0);
				while (true) {
					if (!ss.isClosed()) {
						Socket s = ss.accept();
						new HttpClient(s, storePassword, keyPassword, webroot,
								index, logger,ramanager);
					}
				}
			} catch (JDOMException ex) {
				logger.log(ex.getMessage(), 2);
			} catch (CAManagerException ex) {
				logger.log(ex.getMessage(), 2);
			} catch (IOException ex) {
				logger.log("Conexion no disponible. Socket cerrado.", 1);
			}
		} else {
			logger.log(
					"No se pudo arrancar el servidor, ocurrio una exception.",
					1);
		}

	}

	public void detener() {
		try {
			this.ss.close();
		} catch (IOException ex) {
			logger.log(ex.getMessage(), 2);
		}
		logger.log("Servidor HTTP detenido.", 0);
	}
}
