package com.upm.eui.tfc.scp.manager;

/**
 * Clase encargada de gestionar el envio de correos para los certificados de Clase 1. Esta clase obtiene los datos de configuracion
 * SMTP asi como los datos a enviar en el correo. Con toda esta informacion utiliza la clase SMTPClient que es la encargada
 * de enviar el correo electronico.
 * 
 * @version 1.0
 */

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.cert.X509Certificate;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;

import sun.misc.BASE64Encoder;

import com.upm.eui.tfc.scp.utiles.DigestType;
import com.upm.eui.tfc.scp.utiles.DigestUtil;

public class SMTPManager {

	BASE64Encoder enc = null;
	String aux = "";
	String formato = "";

	public boolean enviarSSL(X509Certificate cert, String CN, String E,
			LogManager logger) {
		FileInputStream sin = null;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		String aux = "";
		String fichero = "";
		String servidor = "";
		int puerto = 25;
		String admin = "";
		int intentos = 3;
		char $ = '$';
		String usuario = "";
		String password = "";
		boolean tsl = false;

		try {
			if (ConfigManager.obtenerParametro("SMTP/PLANTILLAS/CP/ACTIVADA")
					.compareToIgnoreCase("HTML") == 0) {
				formato = "text/html";
			} else {
				formato = "text/plain";
			}

			fichero = ConfigManager.obtenerParametro("SMTP/PLANTILLAS/SSL/"
					+ ConfigManager
							.obtenerParametro("SMTP/PLANTILLAS/SSL/ACTIVADA"));
			servidor = ConfigManager.obtenerParametro("SMTP/SERVIDOR");
			puerto = Integer.parseInt(ConfigManager
					.obtenerParametro("SMTP/PUERTO"));
			admin = ConfigManager.obtenerParametro("SERVIDOR/ADMINISTRADOR");
			intentos = Integer.parseInt(ConfigManager
					.obtenerParametro("SMTP/REINTENTOS"));
			usuario = ConfigManager.obtenerParametro("SMTP/USER");
			password = ConfigManager.obtenerParametro("SMTP/PASSWORD");
			if (ConfigManager.obtenerParametro("SMTP/TSL")
					.compareToIgnoreCase("S") == 0) {
				tsl = true;
			} else {
				tsl = false;
			}

			sin = new FileInputStream(fichero);
			int n = sin.available();
			while ((n = sin.read()) >= 0) {
				aux = "";
				if (((char) n) == $) {
					aux += (char) n;
					if (((char) (n = sin.read())) == $) {
						aux += (char) n;
						while (((char) (n = sin.read())) != $) {
							aux += (char) n;
						}
						aux += (char) n;
						aux += (char) (n = sin.read());
						if (aux.compareToIgnoreCase("$$CN$$") == 0) {
							baos.write(CN.getBytes());
						}
					} else {
						aux = "";
					}
				} else {
					baos.write(n);
				}
			}
			sin.close();

			SMTPClient client = new SMTPClient(servidor, puerto, E, admin,
					"Certificado SSL Clase 1", baos.toByteArray(), intentos,
					logger, cert, formato, usuario, password, tsl);
			baos.close();
			return client.enviarSSL();

		} catch (Exception e) {
			return false;
		}
	}

	public boolean enviarCP(X509Certificate cert, String CN, String E,
			LogManager logger, String Challenge) {
		FileInputStream sin = null;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		enc = new BASE64Encoder();
		String aux = "";
		String fichero = "";
		String servidor = "";
		String URL = "";
		int puerto = 25;
		String pin = "";
		String admin = "";
		int intentos = 3;
		char $ = '$';
		XMLOutputter out = new XMLOutputter();
		Document reg = null;
		SAXBuilder builder = new SAXBuilder();
		Element registro = null;
		Element pendientes = null;
		File f = null;
		FileOutputStream fos = null;
		String usuario = "";
		String password = "";
		boolean tsl = false;

		try {

			if (ConfigManager.obtenerParametro("SMTP/PLANTILLAS/CP/ACTIVADA")
					.compareToIgnoreCase("HTML") == 0) {
				formato = "text/html";
			} else {
				formato = "text/plain";
			}
			fichero = ConfigManager.obtenerParametro("SMTP/PLANTILLAS/CP/"
					+ ConfigManager
							.obtenerParametro("SMTP/PLANTILLAS/CP/ACTIVADA"));
			servidor = ConfigManager.obtenerParametro("SMTP/SERVIDOR");
			URL = ConfigManager.obtenerParametro("CA/URLACTIVA")
					+ "/C1_descargar.htm";
			puerto = Integer.parseInt(ConfigManager
					.obtenerParametro("SMTP/PUERTO"));
			admin = ConfigManager.obtenerParametro("SERVIDOR/ADMINISTRADOR");
			intentos = Integer.parseInt(ConfigManager
					.obtenerParametro("SMTP/REINTENTOS"));
			usuario = ConfigManager.obtenerParametro("SMTP/USER");
			password = ConfigManager.obtenerParametro("SMTP/PASSWORD");
			if (ConfigManager.obtenerParametro("SMTP/TSL").compareToIgnoreCase(
					"S") == 0) {
				tsl = true;
			} else {
				tsl = false;
			}

			pin = DigestUtil
					.getMessageDigest(cert.getEncoded(), DigestType.MD5);

			f = new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/data/" + "pendientes.xml");
			if (!f.exists()) {
				if (f.createNewFile()) {
					fos = new FileOutputStream(f);
					fos
							.write("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><PENDIENTES />"
									.getBytes());
					fos.close();
				} else {
					return false;
				}
			}

			reg = builder.build(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/data/" + "pendientes.xml");

			pendientes = reg.getRootElement();
			registro = new Element("CERTIFICADO");

			registro.addContent(new Element("PIN").setText(pin));
			registro.addContent(new Element("CHALLENGE").setText(DigestUtil
					.getMessageDigest(Challenge.getBytes(), DigestType.MD5)));
			registro.addContent(new Element("CERT").setText(enc.encode(cert
					.getEncoded())));

			pendientes.addContent(registro);

			out.output(pendientes, new FileOutputStream(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/data/" + "pendientes.xml"));

			sin = new FileInputStream(fichero);
			int n = sin.available();
			while ((n = sin.read()) >= 0) {
				aux = "";
				if (((char) n) == $) {
					aux += (char) n;
					if (((char) (n = sin.read())) == $) {
						aux += (char) n;
						while (((char) (n = sin.read())) != $) {
							aux += (char) n;
						}
						aux += (char) n;
						aux += (char) (n = sin.read());
						if (aux.compareToIgnoreCase("$$CN$$") == 0) {
							baos.write(CN.getBytes());
						}
						if (aux.compareToIgnoreCase("$$EMAIL$$") == 0) {
							baos.write(E.getBytes());
						}
						if (aux.compareToIgnoreCase("$$PIN$$") == 0) {
							baos.write(pin.getBytes());
						}
						if (aux.compareToIgnoreCase("$$URL$$") == 0) {
							baos.write(URL.getBytes());
						}

					} else {
						aux = "";
					}
				} else {
					baos.write(n);
				}
			}
			sin.close();
			SMTPClient client = new SMTPClient(servidor, puerto, E, admin,
					"Certificado Personal Clase 1", baos.toByteArray(),
					intentos, logger, null, formato, usuario, password, tsl);
			baos.close();
			return client.enviarCP();

		} catch (Exception e) {
			return false;
		}

	}
}
