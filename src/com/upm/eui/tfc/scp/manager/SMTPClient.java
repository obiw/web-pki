package com.upm.eui.tfc.scp.manager;

import java.io.File;
import java.io.FileOutputStream;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.activation.FileDataSource;
import javax.mail.Authenticator;
import javax.mail.BodyPart;
import javax.mail.Multipart;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Message.RecipientType;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import com.sun.mail.smtp.SMTPTransport;

/**
 * Clase encargada de enviar el correo electronico, gestionando la autenticacion, el SSL/TLS (si se a configurado) y la
 * politica de reintentos.
 * 
 * @version 1.0
 */

public class SMTPClient {
	private String para = "";
	private String de = "";
	private String asunto = "";
	private byte[] mensaje = null;
	private String servidor = "";
	private int reintentos = 0;
	private LogManager logger = null;
	X509Certificate cert = null;
	String formato = "";
	String usuario = "";
	String password = "";
	boolean tsl = false;

	public SMTPClient(String server, int port, String to, String from,
			String subject, byte[] message, int intentos, LogManager log,
			X509Certificate cer, String form, String user, String passw,
			boolean useTSL) {
		servidor = server;
		para = to;
		de = from;
		mensaje = message;
		asunto = subject;
		reintentos = intentos;
		logger = log;
		cert = cer;
		formato = form;
		usuario = user;
		password = passw;
		tsl = useTSL;
	}

	public boolean enviarCP() {
		int cont = 0;
		boolean exito = false;
		boolean validar = true;

		while ((cont < reintentos) && (!exito)) {

			try {

				validar &= (usuario.compareTo("") != 0);
				Properties props = System.getProperties();
				if (validar) {
					props.put("mail.smtp.auth", "true");
				}

				props.put("mail.smtp.host", servidor);

				Session session = Session.getDefaultInstance(props, null);

				MimeMessage message = new MimeMessage(session);

				message.setFrom(new InternetAddress(de));
				message.addRecipient(RecipientType.TO,
						new InternetAddress(para));
				message.setSubject(asunto);
				message.setContent(obtenerMensaje(mensaje), formato);
				message.setSentDate(new Date());
				InternetAddress[] reply = new InternetAddress[1];
				reply[0] = new InternetAddress(de);
				message.setReplyTo(reply);

				SMTPTransport t = (SMTPTransport) session.getTransport("smtp");

				t.setStartTLS(tsl);

				if (validar) {
					t.connect(servidor, usuario, password);
				} else {
					t.connect();
				}
				t.sendMessage(message, message.getAllRecipients());

				return true;
			} catch (Exception ex) {
				ex.printStackTrace();
				cont++;
				logger.log("Fallo al enviar el correo. Quedan "
						+ (reintentos - cont) + " intentos", 1);
			}
		}
		return false;
	}

	/**
	 * obtenerMensaje
	 * 
	 * @param mensaje
	 *            byte[]
	 * @return String
	 */
	private String obtenerMensaje(byte[] mensaje) {
		String aux = "";

		for (int i = 0; i < mensaje.length - 1; i++) {
			aux += (char) mensaje[i];
		}

		return aux;

	}

	public boolean enviarSSL() {
		int cont = 0;
		boolean exito = false;
		String fichero = "";
		boolean validar = true;
		while ((cont < reintentos) && (!exito)) {

			try {
				validar &= (usuario.compareTo("") != 0);
				fichero = ConfigManager
						.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/temp/cert.509";
				FileOutputStream fos = new FileOutputStream(fichero);
				fos.write(cert.getEncoded());
				fos.close();

				Properties props = System.getProperties();

				props.put("mail.smtp.host", servidor);
				if (validar) {
					props.put("mail.smtp.auth", "true");
				}
				Session session = Session.getDefaultInstance(props, null);

				MimeMessage message = new MimeMessage(session);
				message.setFrom(new InternetAddress(de));
				message.addRecipient(RecipientType.TO,
						new InternetAddress(para));
				message.setSubject(asunto);
				message.setSentDate(new Date());
				InternetAddress[] reply = new InternetAddress[1];
				reply[0] = new InternetAddress(de);
				message.setReplyTo(reply);

				BodyPart messageBodyPart = new MimeBodyPart();
				messageBodyPart.setContent(obtenerMensaje(mensaje), formato);

				Multipart multipart = new MimeMultipart();
				multipart.addBodyPart(messageBodyPart);

				messageBodyPart = new MimeBodyPart();
				DataSource source = new FileDataSource(fichero);
				messageBodyPart.setDataHandler(new DataHandler(source));
				messageBodyPart.setFileName("cert.509");
				multipart.addBodyPart(messageBodyPart);

				message.setContent(multipart);

				SMTPTransport t = (SMTPTransport) session.getTransport("smtp");

				t.setStartTLS(tsl);

				if (validar) {
					t.connect(servidor, usuario, password);
				} else {
					t.connect();
				}
				t.sendMessage(message, message.getAllRecipients());

				File f = new File(fichero);
				f.delete();
				return true;
			} catch (Exception ex) {
				cont++;
				logger.log("Fallo al enviar el correo. Quedan "
						+ (reintentos - cont) + " intentos", 1);
			}
		}
		return false;
	}

	public class SMTPAuthenticator extends Authenticator {

		public PasswordAuthentication getPasswordAuthentication() {
			return new PasswordAuthentication(usuario, password);
		}

	}

}
