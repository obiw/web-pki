package com.upm.eui.tfc.scp.http;

/**
 * Clase encargada de implementar el cliente HTTP que recibira las peticiones del servidor HTTP o HTTPS en funcion de la 
 * configuracion. En funcion del metodo y las peticiones servira las paginas web modificando los campos clave ($$) por valores
 * dinamicos de la aplicacion o bien invocara metodos de la Autoridad de Registro para anteder las operaciones sobre certificados
 * recibidas a traves del interfaz web.
 * 
 * @version 1.0
 */

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URLDecoder;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.StringTokenizer;

import org.bouncycastle.util.encoders.Hex;

import sun.misc.BASE64Encoder;

import com.upm.eui.tfc.scp.manager.ConfigManager;
import com.upm.eui.tfc.scp.manager.LogManager;
import com.upm.eui.tfc.scp.manager.RAManager;
import com.upm.eui.tfc.scp.manager.SecurityFileManager;
import com.upm.eui.tfc.scp.utiles.DigestType;
import com.upm.eui.tfc.scp.utiles.DigestUtil;

public class HttpClient extends Thread {

	private Socket sock = null;
	private LogManager logger = null;
	private String docRaiz = "";
	private String fichIndice = "";
	final int maxInputLines = 25;
	final int buffer = 2048;
	private char[] storePassword = null;
	private char[] keyPassword = null;
	public final int RT_GET = 1;
	public final int RT_POST = 3;
	public final int RT_UNSUP = 2;
	public final int RT_END = 4;
	public final int OPE_EMITIR_C1 = 1;
	public final int OPE_EMITIR_C2 = 2;
	public final int OPE_REVOCAR = 3;
	public final int OPE_SUSPENDER = 4;
	public final int OPE_RENOVAR = 6;
	public final int OPE_BUSCAR = 7;
	public final int OPE_DESCARGAR = 8;
	private RAManager ra = null;
	private BASE64Encoder enc = new BASE64Encoder();
	private SecurityFileManager sfm = null;

	public HttpClient(Socket s, char[] pass1, char[] pass2, String docRaiz,
			String fichIndice, LogManager log, RAManager ramanager) {
		this.storePassword = pass1;
		this.keyPassword = pass2;
		this.docRaiz = docRaiz;
		this.fichIndice = fichIndice;
		this.logger = log;
		this.sock = s;
		sfm = new SecurityFileManager();
		this.ra = ramanager;
		this.start();
	}

	// Indica que la petición no está soportada, por ejemplo POST y HEAD
	private void ctrlNoSop(String peticion, OutputStream sout) {
		try {
			if (peticion != null) {
				logger.log("Error 404 - Peticion no soportada", 2);
			}
			sout.write(HttpUtilidades.error(404, "Peticion no soportada",
					peticion));
		} catch (IOException ex) {
			if (peticion != null) {
				logger
						.log(
								"Excepcion de entrada salida. Metodo: ctrlNoSop Peticion: "
										+ peticion + "Excepcion: "
										+ ex.getMessage(), 2);
			}
		}
	}

	// Este m�todo analiza gramaticalmente la solicitud enviada con el
	// GET y la descompone en sus partes para extraer el nombre del
	// archivo que se est� solicitando. Entonces lee el fichero que
	// se pide
	private void ctrlGet(String peticion, OutputStream sout) {
		int fsp = peticion.indexOf(' ');
		int nsp = peticion.indexOf(' ', fsp + 1);
		String fich = peticion.substring(fsp + 1, nsp);

		if (fich.toUpperCase().startsWith("/SERVERCA.HTM")) {
			serverCAGet(fich, sout);
		} else {
			try {
				if (sfm.obtenerFichero(fich)) {
					fich = docRaiz + fich
							+ (fich.endsWith("/") ? fichIndice : "");
					File f = new File(fich);

					if (comprobarFichero(fich, f, sout)) {

						// Ahora lee el fichero que se ha solicitado
						InputStream sin = new FileInputStream(f);
						String cabmime = HttpUtilidades.mimeTypeString(fich);
						int n = sin.available();
						sout.write(HttpUtilidades.cabMime(cabmime, n));
						byte buf[] = new byte[buffer];
						while ((n = sin.read(buf)) >= 0) {
							sout.write(buf, 0, n);

						}
						sin.close();
					}
				} else {
					logger.log(
							"Excepcion de entrada salida. Metodo: ctrlGet Peticion: "
									+ peticion + "Excepcion: Acceso denegado",
							2);
					sout.write(HttpUtilidades.error(404, "Permiso Denegado",
							"No tiene permisos para acceder a esa URL."));
				}
			} catch (IOException ex) {
				logger
						.log(
								"Excepcion de entrada salida. Metodo: ctrlGet Peticion: "
										+ peticion + "Excepcion: "
										+ ex.getMessage(), 2);
			}

		}
	}

	/**
	 * detalle
	 * 
	 * @param fich
	 *            String
	 * @param sout
	 *            OutputStream
	 */
	private void serverCAGet(String pet, OutputStream sOut) {
		String operacion = "";
		String scert = "";
		String fich = "";
		FileInputStream sin = null;
		File f = null;
		String aux = "";
		char $ = '$';
		X509Certificate cert = null;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ByteArrayOutputStream baoscab = new ByteArrayOutputStream();

		pet = pet.replace('?', ',');
		operacion = pet.split(",")[1].split("&")[0].split("=")[1];
		if (operacion.compareToIgnoreCase("detalle") == 0) {
			scert = pet.split(",")[1].split("&")[2].split("=")[1];
			try {
				fich = ConfigManager.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/html/" + "detalle.htm";
				f = new File(fich);

				cert = (X509Certificate) CertificateFactory
						.getInstance("X.509")
						.generateCertificate(
								new FileInputStream(
										ConfigManager
												.obtenerParametro("INSTALACION/DIRECTORIO")
												+ "/html/Repositorio/" + scert));
				if (comprobarFichero(fich, f, sOut)) {
					sin = new FileInputStream(f);
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
								if (aux.compareToIgnoreCase("$$VERSION$$") == 0) {
									baos.write(String
											.valueOf(cert.getVersion())
											.getBytes());
								}
								if (aux.compareToIgnoreCase("$$DESDE$$") == 0) {
									baos.write(cert.getNotBefore().toString()
											.getBytes());
								}
								if (aux.compareToIgnoreCase("$$HASTA$$") == 0) {
									baos.write(cert.getNotAfter().toString()
											.getBytes());
								}
								if (aux.compareToIgnoreCase("$$ASUNTO$$") == 0) {
									baos.write(cert.getSubjectDN().toString()
											.getBytes());
								}
								if (aux.compareToIgnoreCase("$$EMISOR$$") == 0) {
									baos.write(cert.getIssuerDN().toString()
											.getBytes());
								}
								if (aux.compareToIgnoreCase("$$ALGORITMO$$") == 0) {
									baos.write(cert.getSigAlgName().getBytes());
								}
								if (aux.compareToIgnoreCase("$$FICHERO$$") == 0) {
									baos.write(("Repositorio/" + scert)
											.getBytes());
								}
								if (aux.compareToIgnoreCase("$$SERIAL$$") == 0) {
									baos.write(Hex.encode(cert
											.getSerialNumber().toByteArray()));
								}
								if (aux.compareToIgnoreCase("$$ESTADO$$") == 0) {
									baos.write(ra.validar(storePassword, cert)
											.getBytes());
								}
							} else {
								aux = "";
							}

						} else {
							baos.write(n);
						}
					}
					sin.close();
					baoscab.write(HttpUtilidades.cabMime(HttpUtilidades
							.mimeTypeString(fich), baos.size()));
					baoscab.write(baos.toByteArray(), 0, baos.size());
					baoscab.writeTo(sOut);
					baos.close();
					baoscab.close();
				}
			} catch (Exception e) {
				logger.log(ra.getLastError().replaceAll("\n", ""), 2);
				error("error_detalle.htm", ra.getLastError(), sOut);
			}
		}
	}

	@SuppressWarnings("deprecation")
	private String[] getPeticion(DataInputStream sin) {
		try {
			String[] inputLines = new String[maxInputLines];
			int i;
			for (i = 0; i < maxInputLines; i++) {
				inputLines[i] = sin.readLine();
				if (inputLines[i] == null) {
					break;
				}
				if (inputLines[i].length() == 0) {
					if (usingPost(inputLines)) {
						readPostData(inputLines, i, sin);
						i = i + 2;
					}
					break;
				}
			}
			return inputLines;
		} catch (IOException ex) {
			logger.log(
					"Excepcion de entrada salida. Metodo: getPeticion Excepcion: "
							+ ex.getMessage(), 2);
			return (null);
		}
	}

	private int tipoPeticion(String peticion) {
		if (peticion != null) {
			if (peticion.toUpperCase().startsWith("GET")) {
				return RT_GET;
			} else if (peticion.toUpperCase().startsWith("POST")) {
				return RT_POST;
			} else {
				return RT_UNSUP;
			}
		} else {
			return RT_UNSUP;
		}
	}

	// Funci�n principal de nuestro servidor, que se conecta al socket
	// y se embucla indefinidamente
	public void run() {
		String[] peticion = null;

		try {
			OutputStream sOut = sock.getOutputStream();
			DataInputStream sIn = new DataInputStream(new BufferedInputStream(
					sock.getInputStream()));
			if ((peticion = getPeticion(sIn)) != null) {
				switch (tipoPeticion(peticion[0])) {
				case RT_GET:
					ctrlGet(peticion[0], sOut);
					break;
				case RT_POST:
					ctrlPost(peticion, sOut);
					break;
				case RT_UNSUP:
				default:
					ctrlNoSop(peticion[0], sOut);
					break;
				}
			}
			sOut.close();
			sIn.close();
			sock.close();
		} catch (IOException ex) {
			if (peticion != null) {
				logger.log(
						"Excepcion de entrada salida. Metodo: run Excepcion: "
								+ ex.getMessage(), 2);
			}
		}

	}

	/**
	 * ctrlPost
	 * 
	 * @param peticion
	 *            String[]
	 * @param sOut
	 *            OutputStream
	 */
	private void ctrlPost(String[] peticion, OutputStream sOut) {
		int fsp = peticion[0].indexOf(' ');
		int nsp = peticion[0].indexOf(' ', fsp + 1);
		String fich = peticion[0].substring(fsp + 1, nsp);
		Hashtable<Object, Object> parametros = new Hashtable<Object, Object>();
		String[] param = null;
		int i;

		if (fich.compareToIgnoreCase("/serverCA.htm") == 0) {

			for (i = 0; i < peticion.length; i++) {
				if (peticion[i].compareToIgnoreCase("") == 0) {
					break;
				}
			}

			param = peticion[++i].split("&");

			for (i = 0; i < param.length; i++) {
				try {
					if (param[i].split("=").length > 1) {
						parametros.put(URLDecoder.decode(
								param[i].split("=")[0], "ISO-8859-1"),
								URLDecoder.decode(param[i].split("=")[1],
										"ISO-8859-1"));
					}
				} catch (Exception e) {
					ctrlNoSop(peticion[0], sOut);
				}
			}
			serverCAPost(parametros, sOut);
		} else {
			ctrlNoSop(peticion[0], sOut);
		}
	}

	/**
	 * serverCA
	 * 
	 * @param parametros
	 *            Hashtable
	 * @param sOut
	 *            OutputStream
	 */
	private void serverCAPost(Hashtable<Object, Object> parametros,
			OutputStream sOut) {
		switch (seleccionarOperacion(parametros)) {
		case OPE_EMITIR_C2:
			emitirClase2(parametros, sOut);
			break;
		case OPE_EMITIR_C1:
			emitirClase1(parametros, sOut);
			break;
		case OPE_BUSCAR:
			buscar(parametros, sOut);
			break;
		case OPE_REVOCAR:
			revocar(parametros, sOut);
			break;
		case OPE_SUSPENDER:
			suspender(parametros, sOut);
			break;
		case OPE_RENOVAR:
			renovar(parametros, sOut);
			break;
		case OPE_DESCARGAR:
			descargar(parametros, sOut);
			break;

		}
	}

	/**
	 * descargar
	 * 
	 * @param parametros
	 *            Hashtable
	 * @param sOut
	 *            OutputStream
	 */
	private void descargar(Hashtable<Object, Object> parametros,
			OutputStream sOut) {
		String fich = null;
		File f = null;
		InputStream sin = null;
		X509Certificate cert = null;
		char $ = '$';
		String aux = "";
		String navegador = "";
		String CH = "";
		String PIN = "";

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ByteArrayOutputStream baoscab = new ByteArrayOutputStream();

		if (parametros.containsKey("PIN")) {
			PIN = parametros.get("PIN").toString();
		}

		if (parametros.containsKey("CH")) {
			CH = parametros.get("CH").toString();
		}

		if (parametros.containsKey("operacion")) {
			navegador = parametros.get("operacion").toString().split("_")[1];
		}

		logger.log(
				"Peticion recibida: <operacion=Descargar Certificado Clase 1,PIN-CODE="
						+ PIN + "> Procesando", 0);
		cert = ra.descargar(PIN, CH);

		try {
			if (cert == null) {
				logger.log(ra.getLastError().replaceAll("\n", ""), 2);
				error("error.htm", ra.getLastError(), sOut);
			} else {
				if (navegador.compareToIgnoreCase("MS") == 0) {
					fich = ConfigManager
							.obtenerParametro("INSTALACION/DIRECTORIO")
							+ "/html/" + "C1_instalarMS.htm";
					f = new File(fich);
					if (comprobarFichero(fich, f, sOut)) {
						sin = new FileInputStream(f);
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
									if (aux.compareToIgnoreCase("$$DN$$") == 0) {
										baos.write(cert.getSubjectDN()
												.toString().getBytes());
									}
									if (aux.compareToIgnoreCase("$$SERIAL$$") == 0) {
										baos.write(Hex.encode(cert
												.getSerialNumber()
												.toByteArray()));
									}
									if (aux
											.compareToIgnoreCase("$$CERTIFICADO1$$") == 0) {
										baos.write(formatearCert(cert)
												.getBytes());
									}
									if (aux
											.compareToIgnoreCase("$$CERTIFICADO2$$") == 0) {
										baos.write((enc.encode(cert
												.getEncoded())).getBytes());
									}
								} else {
									aux = "";
								}

							} else {
								baos.write(n);
							}
						}
						sin.close();
						baoscab.write(HttpUtilidades.cabMime(HttpUtilidades
								.mimeTypeString(fich),
								baos.toByteArray().length));
						baoscab.write(baos.toByteArray(), 0, baos.size());
						baoscab.writeTo(sOut);
						baoscab.close();
						baos.close();
						logger.log("Certificado Descargado: <dn="
								+ cert.getSubjectDN().toString() + ">", 0);
					}
				} else {
					fich = ConfigManager
							.obtenerParametro("INSTALACION/DIRECTORIO")
							+ "/html/" + "C1_instalarNS.htm";
					f = new File(fich);
					if (comprobarFichero(fich, f, sOut)) {
						sin = new FileInputStream(f);
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
									if (aux.compareToIgnoreCase("$$DN$$") == 0) {
										baos.write(cert.getSubjectDN()
												.toString().getBytes());
									}
									if (aux.compareToIgnoreCase("$$SERIAL$$") == 0) {
										baos.write(Hex.encode(cert
												.getSerialNumber()
												.toByteArray()));
									}
									if (aux
											.compareToIgnoreCase("$$CERTIFICADO$$") == 0) {
										baos.write(cert.getEncoded());
									}
								} else {
									aux = "";
								}

							} else {
								baos.write(n);
							}
						}
						sin.close();
						baoscab.write(HttpUtilidades.cabMime(HttpUtilidades
								.mimeTypeString(".mix"),
								baos.toByteArray().length));
						baoscab.write(baos.toByteArray(), 0, baos.size());
						baoscab.writeTo(sOut);
						baoscab.close();
						baos.close();
						logger.log("Certificado Descargado: <dn="
								+ cert.getSubjectDN().toString() + ">", 0);
					}
				}
			}
		} catch (Exception ex) {
			logger.log(ra.getLastError().replaceAll("\n", ""), 2);
			error("error.htm", ra.getLastError(), sOut);
		}
	}

	/**
	 * renovar
	 * 
	 * @param parametros
	 *            Hashtable
	 * @param sOut
	 *            OutputStream
	 */
	private void renovar(Hashtable<Object, Object> parametros, OutputStream sOut) {
		if (parametros.get("operacion").toString().endsWith("cp")) {
			renovarCP(parametros, sOut);
		} else {
			renovarSSL(parametros, sOut);
		}

	}

	/**
	 * renovarSSL
	 * 
	 * @param parametros
	 *            Hashtable
	 * @param sOut
	 *            OutputStream
	 */
	private void renovarSSL(Hashtable<Object, Object> parametros,
			OutputStream sOut) {
		String fich = null;
		File f = null;
		InputStream sin = null;
		X509Certificate cert = null;
		char $ = '$';
		String aux = "";
		String CN = "";
		String E = "";
		String C = "";
		String S = "";
		String L = "";
		String CH = "";
		String csr = "";
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ByteArrayOutputStream baoscab = new ByteArrayOutputStream();

		if (parametros.containsKey("CN")) {
			CN = parametros.get("CN").toString();
		}
		if (parametros.containsKey("E")) {
			E = parametros.get("E").toString();
		}
		if (parametros.containsKey("challenge")) {
			CH = parametros.get("challenge").toString();
		}
		if (parametros.containsKey("csr")) {
			csr = parametros.get("csr").toString();
		}

		logger.log(
				"Peticion recibida: <operacion=Renovar Certificado Servidor Seguro Clase 2,CN="
						+ CN + ",E=" + E + ",C=" + C + ",S=" + S + ",L=" + L
						+ "> Procesando", 0);
		cert = ra.renovarSSL(CN, E, CH, csr, storePassword, keyPassword);

		try {
			if (cert == null) {
				error("error.htm", ra.getLastError(), sOut);
			} else {

				fich = ConfigManager.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/html/" + "C2_instalar_ssl.htm";
				f = new File(fich);
				if (comprobarFichero(fich, f, sOut)) {
					sin = new FileInputStream(f);
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
								if (aux.compareToIgnoreCase("$$DN$$") == 0) {
									baos.write((ra.invertirCadena(cert
											.getSubjectDN().toString()))
											.getBytes());
								}
								if (aux.compareToIgnoreCase("$$SERIAL$$") == 0) {
									baos.write(Hex.encode(cert
											.getSerialNumber().toByteArray()));
								}
								if (aux.compareToIgnoreCase("$$CERTIFICADO$$") == 0) {
									baos
											.write(("-----BEGIN CERTIFICATE-----<br>\n"
													+ enc.encode(cert
															.getEncoded()) + "<br>-----END CERTIFICATE-----")
													.getBytes());
								}
							} else {
								aux = "";
							}

						} else {
							baos.write(n);
						}
					}
					sin.close();
					baoscab.write(HttpUtilidades.cabMime(HttpUtilidades
							.mimeTypeString(fich), baos.toByteArray().length));
					baoscab.write(baos.toByteArray(), 0, baos.size());
					baoscab.writeTo(sOut);
					baoscab.close();
					baos.close();
					logger.log("Certificado Clase 2 renovado: <dn="
							+ cert.getSubjectDN().toString() + ">", 0);
				}
			}
			sOut.close();
		} catch (Exception ex) {
			logger.log(ra.getLastError().replaceAll("\n", ""), 2);
			error("error.htm", ra.getLastError(), sOut);
		}

	}

	/**
	 * renovarCP
	 * 
	 * @param parametros
	 *            Hashtable
	 * @param sOut
	 *            OutputStream
	 */
	private void renovarCP(Hashtable<Object, Object> parametros,
			OutputStream sOut) {
		String fich = null;
		File f = null;
		InputStream sin = null;
		X509Certificate cert = null;
		char $ = '$';
		String aux = "";
		String navegador = "";
		String CN = "";
		String E = "";
		String C = "";
		String S = "";
		String L = "";
		String CH = "";
		String PK = "";
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ByteArrayOutputStream baoscab = new ByteArrayOutputStream();

		if (parametros.containsKey("CN")) {
			CN = parametros.get("CN").toString();
		}
		if (parametros.containsKey("E")) {
			E = parametros.get("E").toString();
		}
		if (parametros.containsKey("C")) {
			C = parametros.get("C").toString();
		}
		if (parametros.containsKey("S")) {
			S = parametros.get("S").toString();
		}
		if (parametros.containsKey("L")) {
			L = parametros.get("L").toString();
		}
		if (parametros.containsKey("challenge")) {
			CH = parametros.get("challenge").toString();
		}
		if (parametros.containsKey("public_key")) {
			PK = parametros.get("public_key").toString();
		}

		if (parametros.containsKey("operacion")) {
			navegador = parametros.get("operacion").toString().split("_")[1];
		}

		logger.log(
				"Peticion recibida: <operacion=Renovar Certificado Personal Clase 2,CN="
						+ CN + ",E=" + E + ",C=" + C + ",S=" + S + ",L=" + L
						+ "> Procesando", 0);
		cert = ra.renovarCP(CN, E, C, S, L, CH, PK, storePassword, keyPassword,
				navegador);

		try {
			if (cert == null) {
				logger.log(ra.getLastError().replaceAll("\n", ""), 2);
				error("error.htm", ra.getLastError(), sOut);
			} else {
				if (navegador.compareToIgnoreCase("MS") == 0) {
					fich = ConfigManager
							.obtenerParametro("INSTALACION/DIRECTORIO")
							+ "/html/" + "C2_instalarMS.htm";
					f = new File(fich);
					if (comprobarFichero(fich, f, sOut)) {
						sin = new FileInputStream(f);
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
									if (aux.compareToIgnoreCase("$$DN$$") == 0) {
										baos.write((ra.invertirCadena(cert
												.getSubjectDN().toString()))
												.getBytes());
									}
									if (aux.compareToIgnoreCase("$$SERIAL$$") == 0) {
										baos.write(Hex.encode(cert
												.getSerialNumber()
												.toByteArray()));
									}
									if (aux
											.compareToIgnoreCase("$$CERTIFICADO$$") == 0) {
										baos.write(formatearCert(cert)
												.getBytes());
									}
								} else {
									aux = "";
								}

							} else {
								baos.write(n);
							}
						}
						sin.close();
						baoscab.write(HttpUtilidades.cabMime(HttpUtilidades
								.mimeTypeString(fich),
								baos.toByteArray().length));
						baoscab.write(baos.toByteArray(), 0, baos.size());
						baoscab.writeTo(sOut);
						baoscab.close();
						baos.close();
						logger.log("Certificado Clase 2 renovado: <dn="
								+ cert.getSubjectDN().toString() + ">", 0);
					}
				} else {
					fich = ConfigManager
							.obtenerParametro("INSTALACION/DIRECTORIO")
							+ "/html/" + "C2_instalarNS.htm";
					f = new File(fich);
					if (comprobarFichero(fich, f, sOut)) {
						sin = new FileInputStream(f);
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
									if (aux.compareToIgnoreCase("$$DN$$") == 0) {
										baos.write(cert.getSubjectDN()
												.toString().getBytes());
									}
									if (aux.compareToIgnoreCase("$$SERIAL$$") == 0) {
										baos.write(Hex.encode(cert
												.getSerialNumber()
												.toByteArray()));
									}
									if (aux
											.compareToIgnoreCase("$$CERTIFICADO$$") == 0) {
										baos.write(cert.getEncoded());
									}
								} else {
									aux = "";
								}

							} else {
								baos.write(n);
							}
						}
						sin.close();
						baoscab.write(HttpUtilidades.cabMime(HttpUtilidades
								.mimeTypeString(".mix"),
								baos.toByteArray().length));
						baoscab.write(baos.toByteArray(), 0, baos.size());
						baoscab.writeTo(sOut);
						baoscab.close();
						baos.close();
						logger.log("Certificado Clase 2 renovado: <dn="
								+ cert.getSubjectDN().toString() + ">", 0);
					}
				}
			}
			sOut.close();
		} catch (Exception ex) {
			logger.log(ra.getLastError().replaceAll("\n", ""), 2);
			error("error.htm", ra.getLastError(), sOut);
		}

	}

	/**
	 * suspender
	 * 
	 * @param parametros
	 *            Hashtable
	 * @param sOut
	 *            OutputStream
	 */
	private void suspender(Hashtable<Object, Object> parametros,
			OutputStream sOut) {
		String fich = "";
		String cn = "";
		String e = "";
		String challenge = "";
		String aux = "";
		char $ = '$';
		X509Certificate cert = null;
		File f = null;
		FileInputStream sin = null;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ByteArrayOutputStream baoscab = new ByteArrayOutputStream();
		Object[] retorno = null;
		boolean exito = false;
		String accion = "";
		if (parametros.containsKey("serial")) {
		}
		if (parametros.containsKey("CN")) {
			cn = parametros.get("CN").toString();
		}
		if (parametros.containsKey("E")) {
			e = parametros.get("E").toString();
		}
		if (parametros.containsKey("accion")) {
			accion = parametros.get("accion").toString();
		}
		if (parametros.containsKey("challenge")) {
			challenge = parametros.get("challenge").toString();
		}

		retorno = ra.buscar(cn, e, "");
		if (retorno != null) {
			cert = (X509Certificate) retorno[1];
		} else {
			error("error.htm", ra.getLastError(), sOut);
		}

		if (cert == null) {
			error("error.htm", ra.getLastError(), sOut);
		} else {
			if (accion.compareToIgnoreCase("Z") == 0) {
				logger.log(
						"Peticion recibida: <operacion=Suspender Certificado Clase 2,dn="
								+ cert.getSubjectDN().toString()
								+ "> Procesando", 0);
			} else {
				logger.log(
						"Peticion recibida: <operacion=Reactivar Certificado Clase 2,dn="
								+ cert.getSubjectDN().toString()
								+ "> Procesando", 0);
			}

			try {
				exito = ra.suspender(cert, storePassword, keyPassword, accion,
						cn, e, challenge);
				if (exito) {
					if (accion.compareToIgnoreCase("Z") == 0) {
						fich = ConfigManager
								.obtenerParametro("INSTALACION/DIRECTORIO")
								+ "/html/" + "suspension_correcta.htm";
						logger.log("Certificado Suspendido: <dn="
								+ cert.getSubjectDN().toString() + ">", 0);
					} else {
						fich = ConfigManager
								.obtenerParametro("INSTALACION/DIRECTORIO")
								+ "/html/" + "reactivacion_correcta.htm";
						logger.log("Certificado Reactivado: <dn="
								+ cert.getSubjectDN().toString() + ">", 0);
					}
					f = new File(fich);
					if (comprobarFichero(fich, f, sOut)) {
						sin = new FileInputStream(f);
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
									if (aux.compareToIgnoreCase("$$ACCION$$") == 0) {
										if (accion.compareToIgnoreCase("Z") == 0) {
											baos.write("Suspensi�n".getBytes());
										} else {
											baos.write("Reactivaci�n"
													.getBytes());
										}
									}
								} else {
									aux = "";
								}

							} else {
								baos.write(n);
							}

						}
						sin.close();
						baoscab.write(HttpUtilidades.cabMime(HttpUtilidades
								.mimeTypeString(fich),
								baos.toByteArray().length));
						baoscab.write(baos.toByteArray(), 0, baos.size());
						baoscab.writeTo(sOut);
						baoscab.close();
						baos.close();

					}
				} else {
					logger.log(ra.getLastError().replaceAll("\n", ""), 2);
					error("error.htm", ra.getLastError(), sOut);
				}
			} catch (Exception ex) {
				logger.log(ra.getLastError().replaceAll("\n", ""), 0);
				error("error.htm", ra.getLastError(), sOut);
			}
		}

	}

	/**
	 * revocar
	 * 
	 * @param parametros
	 *            Hashtable
	 * @param sOut
	 *            OutputStream
	 */
	private void revocar(Hashtable<Object, Object> parametros, OutputStream sOut) {
		String fich = "";
		String cn = "";
		String e = "";
		String challenge = "";
		X509Certificate cert = null;
		String aux = "";
		File f = null;
		FileInputStream sin = null;
		char $ = '$';
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ByteArrayOutputStream baoscab = new ByteArrayOutputStream();
		Object[] retorno = null;
		int motivo = 1;
		boolean exito = false;

		if (parametros.containsKey("serial")) {
		}
		if (parametros.containsKey("CN")) {
			cn = parametros.get("CN").toString();
		}
		if (parametros.containsKey("E")) {
			e = parametros.get("E").toString();
		}
		if (parametros.containsKey("motivo")) {
			motivo = Integer.parseInt(parametros.get("motivo").toString());
		}
		if (parametros.containsKey("challenge")) {
			challenge = parametros.get("challenge").toString();
		}

		retorno = ra.buscar(cn, e, "");
		if (retorno != null) {
			cert = (X509Certificate) retorno[1];
		} else {
			logger.log(ra.getLastError().replaceAll("\n", ""), 2);
			error("error.htm", ra.getLastError(), sOut);
		}

		if (cert == null) {
			logger.log(ra.getLastError().replaceAll("\n", ""), 2);
			error("error.htm", ra.getLastError(), sOut);
		} else {
			logger.log(
					"Peticion recibida: <operacion=Revocar Certificado Clase 2,dn="
							+ cert.getSubjectDN().toString() + "> Procesando",
					0);
			try {
				exito = ra.revocar(cert, storePassword, keyPassword, motivo,
						cn, e, challenge);
				if (exito) {
					fich = ConfigManager
							.obtenerParametro("INSTALACION/DIRECTORIO")
							+ "/html/" + "revocacion_correcta.htm";
					f = new File(fich);
					if (comprobarFichero(fich, f, sOut)) {
						sin = new FileInputStream(f);
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
									if (aux.compareToIgnoreCase("$$ACCION$$") == 0) {
										baos.write("Revocaci�n".getBytes());
									}
								} else {
									aux = "";
								}

							} else {
								baos.write(n);
							}

						}
						sin.close();
						baoscab.write(HttpUtilidades.cabMime(HttpUtilidades
								.mimeTypeString(fich),
								baos.toByteArray().length));
						baoscab.write(baos.toByteArray(), 0, baos.size());
						baoscab.writeTo(sOut);
						baoscab.close();
						baos.close();
						logger.log("Certificado Revocado: <dn="
								+ cert.getSubjectDN().toString() + ">", 0);
					}
				} else {
					logger.log(ra.getLastError().replaceAll("\n", ""), 2);
					error("error.htm", ra.getLastError(), sOut);
				}
			} catch (Exception ex) {
				logger.log(ra.getLastError().replaceAll("\n", ""), 2);
				error("error.htm", ra.getLastError(), sOut);
			}
		}
	}

	/**
	 * buscar
	 * 
	 * @param parametros
	 *            Hashtable
	 * @param sOut
	 *            OutputStream
	 */
	private void buscar(Hashtable<Object, Object> parametros, OutputStream sOut) {
		String fich = "";
		String cn = "";
		String e = "";
		X509Certificate cert = null;
		String destino = "";
		String aux = "";
		File f = null;
		FileInputStream sin = null;
		char $ = '$';
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ByteArrayOutputStream baoscab = new ByteArrayOutputStream();
		Object[] retorno = null;
		String filename = "";
		String tipo = "";

		if (parametros.containsKey("serial")) {
		}
		if (parametros.containsKey("CN")) {
			cn = parametros.get("CN").toString();
		}
		if (parametros.containsKey("E")) {
			e = parametros.get("E").toString();
		}
		if (parametros.containsKey("tipo")) {
			tipo = parametros.get("tipo").toString();
		}

		retorno = ra.buscar(cn, e, tipo);

		if (retorno != null) {
			cert = (X509Certificate) retorno[1];
			filename = retorno[0].toString();
			destino = parametros.get("destino").toString();
			if ((cert == null) || (destino.compareToIgnoreCase("") == 0)) {
				if (destino.compareToIgnoreCase("detalle") == 0) {
					error("error_detalle.htm", ra.getLastError(), sOut);
				} else {
					error("error.htm", ra.getLastError(), sOut);
				}

			} else {
				try {
					fich = ConfigManager
							.obtenerParametro("INSTALACION/DIRECTORIO")
							+ "/html/" + destino + ".htm";
					f = new File(fich);
					if (comprobarFichero(fich, f, sOut)) {
						sin = new FileInputStream(f);
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
									if (aux.compareToIgnoreCase("$$VERSION$$") == 0) {
										baos.write(String.valueOf(
												cert.getVersion()).getBytes());
									}
									if (aux.compareToIgnoreCase("$$DESDE$$") == 0) {
										baos.write(cert.getNotBefore()
												.toString().getBytes());
									}
									if (aux.compareToIgnoreCase("$$HASTA$$") == 0) {
										baos.write(cert.getNotAfter()
												.toString().getBytes());
									}
									if (aux.compareToIgnoreCase("$$ASUNTO$$") == 0) {
										baos.write(cert.getSubjectDN()
												.toString().getBytes());
									}
									if (aux.compareToIgnoreCase("$$EMISOR$$") == 0) {
										baos.write(cert.getIssuerDN()
												.toString().getBytes());
									}
									if (aux
											.compareToIgnoreCase("$$ALGORITMO$$") == 0) {
										baos.write(cert.getSigAlgName()
												.getBytes());
									}
									if (aux.compareToIgnoreCase("$$SERIAL$$") == 0) {
										baos.write(Hex.encode(cert
												.getSerialNumber()
												.toByteArray()));
									}
									if (aux.compareToIgnoreCase("$$ESTADO$$") == 0) {
										baos.write(ra.validar(storePassword,
												cert).getBytes());
									}
									if (aux.compareToIgnoreCase("$$FICHERO$$") == 0) {
										baos.write(("Repositorio/" + filename)
												.getBytes());
									}
									if (aux.compareToIgnoreCase("$$CN$$") == 0) {
										baos.write(retorno[6].toString()
												.getBytes());
									}
									if (aux.compareToIgnoreCase("$$EMAIL$$") == 0) {
										baos.write(retorno[5].toString()
												.getBytes());
									}
									if (aux.compareToIgnoreCase("$$C$$") == 0) {
										baos.write(retorno[2].toString()
												.getBytes());
									}
									if (aux.compareToIgnoreCase("$$S$$") == 0) {
										baos.write(retorno[3].toString()
												.getBytes());
									}
									if (aux.compareToIgnoreCase("$$L$$") == 0) {
										baos.write(retorno[4].toString()
												.getBytes());
									}

								} else {
									aux = "";
								}

							} else {
								baos.write(n);
							}
						}
						sin.close();
						baoscab.write(HttpUtilidades.cabMime(HttpUtilidades
								.mimeTypeString(fich),
								baos.toByteArray().length));
						baoscab.write(baos.toByteArray(), 0, baos.size());
						baoscab.writeTo(sOut);
						baoscab.close();
						baos.close();
					}
				} catch (Exception ex) {
					error("error.htm", "No se encontro el certificado.", sOut);
				}
			}

		} else {
			error("error.htm", "No se encontro el certificado.", sOut);
		}

	}

	/**
	 * error
	 * 
	 * @param string
	 *            String
	 * @param ERROR_BUSCAR
	 *            String
	 * @param sOut
	 *            OutputStream
	 */
	private void error(String pagina, String mensaje, OutputStream sOut) {
		String fich = null;
		File f = null;
		InputStream sin = null;
		char $ = '$';
		String aux = "";
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ByteArrayOutputStream baoscab = new ByteArrayOutputStream();

		try {
			logger.log(mensaje, 2);
			fich = ConfigManager.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/html/" + pagina;
			f = new File(fich);
			if (comprobarFichero(fich, f, sOut)) {
				sin = new FileInputStream(f);
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
							if (aux.compareToIgnoreCase("$$ERROR$$") == 0) {
								baos.write(mensaje.getBytes());
							}
						} else {
							aux = "";
						}

					} else {
						baos.write(n);
					}
				}
				sin.close();
				baoscab.write(HttpUtilidades.cabMime(HttpUtilidades
						.mimeTypeString(fich), baos.toByteArray().length));
				baoscab.write(baos.toByteArray(), 0, baos.size());
				baoscab.writeTo(sOut);
				baoscab.close();
				baos.close();
			}
		} catch (Exception ex) {
			ctrlNoSop(mensaje, sOut);
		}
	}

	/**
	 * emitir
	 * 
	 * @param parametros
	 *            Hashtable
	 * @param sOut
	 *            OutputStream
	 */
	private void emitirClase2(Hashtable<Object, Object> parametros,
			OutputStream sOut) {
		String fich = null;
		File f = null;
		InputStream sin = null;
		X509Certificate cert = null;
		int tipo = 0;
		char $ = '$';
		String aux = "";
		String navegador = "";
		String CN = "";
		String E = "";
		String C = "";
		String S = "";
		String L = "";
		String CH = "";
		String PK = "";
		String csr = "";
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ByteArrayOutputStream baoscab = new ByteArrayOutputStream();

		if (parametros.containsKey("CN")) {
			CN = parametros.get("CN").toString();
		}
		if (parametros.containsKey("E")) {
			E = parametros.get("E").toString();
		}
		if (parametros.containsKey("C")) {
			C = parametros.get("C").toString();
		}
		if (parametros.containsKey("S")) {
			S = parametros.get("S").toString();
		}
		if (parametros.containsKey("L")) {
			L = parametros.get("L").toString();
		}
		if (parametros.containsKey("CH1")) {
			CH = parametros.get("CH1").toString();
		}
		if (parametros.containsKey("public_key")) {
			PK = parametros.get("public_key").toString();
		}

		if (parametros.containsKey("csr")) {
			csr = parametros.get("csr").toString();
		}

		if (parametros.containsKey("operacion")) {
			navegador = parametros.get("operacion").toString().split("_")[1];
			if (parametros.get("operacion").toString().split("_")[2]
					.compareToIgnoreCase("cp") == 0) {
				tipo = 0;
			} else {
				tipo = 1;
			}
		}

		if (tipo == 0) {
			logger.log(
					"Peticion recibida: <operacion=Emitir Certificado Personal Clase 2,CN="
							+ CN + ",E=" + E + ",C=" + C + ",S=" + S + ",L="
							+ L + "> Procesando", 0);
			cert = ra.emitirCP(CN, E, C, S, L, CH, PK, storePassword,
					keyPassword, navegador, 2);
		} else {
			logger
					.log(
							"Peticion recibida: <operacion=Emitir Certificado Servidor Web Seguro Clase 2,CN="
									+ CN + ",E=" + E + "> Procesando", 0);
			cert = ra.emitirSSL(CN, E, CH, csr, storePassword, keyPassword, 2);
		}

		try {
			if (cert == null) {
				error("error.htm", ra.getLastError(), sOut);
			} else {
				if (tipo == 0) {
					if (navegador.compareToIgnoreCase("MS") == 0) {
						fich = ConfigManager
								.obtenerParametro("INSTALACION/DIRECTORIO")
								+ "/html/" + "C2_instalarMS.htm";
						f = new File(fich);
						if (comprobarFichero(fich, f, sOut)) {
							sin = new FileInputStream(f);
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
										if (aux.compareToIgnoreCase("$$DN$$") == 0) {
											baos
													.write((ra
															.invertirCadena(cert
																	.getSubjectDN()
																	.toString()))
															.getBytes());
										}
										if (aux
												.compareToIgnoreCase("$$SERIAL$$") == 0) {
											baos.write(Hex.encode(cert
													.getSerialNumber()
													.toByteArray()));
										}
										if (aux
												.compareToIgnoreCase("$$CERTIFICADO1$$") == 0) {
											baos.write(formatearCert(cert)
													.getBytes());
										}
										if (aux
												.compareToIgnoreCase("$$CERTIFICADO2$$") == 0) {
											baos.write((enc.encode(cert
													.getEncoded())).getBytes());
										}
									} else {
										aux = "";
									}

								} else {
									baos.write(n);
								}
							}
							sin.close();
							baoscab.write(HttpUtilidades.cabMime(HttpUtilidades
									.mimeTypeString(fich),
									baos.toByteArray().length));
							baoscab.write(baos.toByteArray(), 0, baos.size());
							baoscab.writeTo(sOut);
							baoscab.close();
							baos.close();
							logger.log("Certificado Clase 2 emitido: <dn="
									+ cert.getSubjectDN().toString() + ">", 0);
						}
					} else {
						fich = ConfigManager
								.obtenerParametro("INSTALACION/DIRECTORIO")
								+ "/html/" + "C2_instalarNS.htm";
						
						f = new File(fich);
						if (comprobarFichero(fich, f, sOut)) {
							sin = new FileInputStream(f);
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
										if (aux.compareToIgnoreCase("$$DN$$") == 0) {
											baos.write(cert.getSubjectDN()
													.toString().getBytes());
										}
										if (aux
												.compareToIgnoreCase("$$SERIAL$$") == 0) {
											baos.write(Hex.encode(cert
													.getSerialNumber()
													.toByteArray()));
										}
										if (aux
												.compareToIgnoreCase("$$CERTIFICADO$$") == 0) {
											baos.write(cert.getEncoded());
										}
									} else {
										aux = "";
									}

								} else {
									baos.write(n);
								}
							}
							sin.close();
							baoscab.write(HttpUtilidades.cabMime(HttpUtilidades
									.mimeTypeString(".mix"),
									baos.toByteArray().length));
							baoscab.write(baos.toByteArray(), 0, baos.size());
							baoscab.writeTo(sOut);
							baoscab.close();
							baos.close();
							logger.log("Certificado Clase 2 emitido: <dn="
									+ cert.getSubjectDN().toString() + ">", 0);
						}
					}

				} else {
					fich = ConfigManager
							.obtenerParametro("INSTALACION/DIRECTORIO")
							+ "/html/" + "C2_instalar_ssl.htm";
					String filename = "Repositorio/" + DigestUtil.getMessageDigest(cert.getEncoded(),
							DigestType.MD5).replace(':', '_')
							+ ".cer";
					f = new File(fich);
					if (comprobarFichero(fich, f, sOut)) {
						sin = new FileInputStream(f);
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
									if (aux.compareToIgnoreCase("$$DN$$") == 0) {
										baos.write((ra.invertirCadena(cert
												.getSubjectDN().toString()))
												.getBytes());
									}
									if (aux.compareToIgnoreCase("$$SERIAL$$") == 0) {
										baos.write(Hex.encode(cert
												.getSerialNumber()
												.toByteArray()));
									}
									if (aux
											.compareToIgnoreCase("$$CERTIFICADO$$") == 0) {
										baos
												.write(filename.getBytes());
									}
								} else {
									aux = "";
								}

							} else {
								baos.write(n);
							}
						}
						sin.close();
						baoscab.write(HttpUtilidades.cabMime(HttpUtilidades
								.mimeTypeString(fich),
								baos.toByteArray().length));
						baoscab.write(baos.toByteArray(), 0, baos.size());
						baoscab.writeTo(sOut);
						baoscab.close();
						baos.close();
						logger.log("Certificado Clase 2 emitido: <dn="
								+ cert.getSubjectDN().toString() + ">", 0);
					}
					sOut.close();
				}
			}
		} catch (Exception ex) {
			logger.log(ra.getLastError().replaceAll("\n", ""), 2);
			error("error.htm", ra.getLastError(), sOut);
		}
	}

	/**
	 * formatearCert
	 * 
	 * @param cert
	 *            X509Certificate
	 * @return String
	 */
	private String formatearCert(X509Certificate cert) {
		String aux1 = "";
		String aux2 = "";

		try {
			aux1 = enc.encode(cert.getEncoded());
			for (int j = 0; j < aux1.length(); j++) {
				if (aux1.charAt(j) == '\n' || aux1.charAt(j) == '\r') {
					aux2 += "\" & _ \n\"";
					j++;
				} else {
					aux2 += aux1.charAt(j);
				}
			}
			return aux2;
		} catch (Exception ex) {
			return null;
		}
	}

	/**
	 * comprobarFichero
	 * 
	 * @param f
	 *            File
	 * @param sOut
	 *            OutputStream
	 * @return boolean
	 */
	private boolean comprobarFichero(String fich, File f, OutputStream sOut) {
		try {
			if (!f.exists()) {
				logger.log("Error 404: Fichero " + f.getAbsolutePath()
						+ " no existe", 2);
				sOut.write(HttpUtilidades.error(404, "No Encontrado",
						"La URL solicitada no se encuentra en este servidor."));
				return false;
			}

			if (!f.canRead()) {
				logger.log("Error 404: No se puede leer el fichero "
						+ f.getAbsolutePath(), 2);
				sOut.write(HttpUtilidades.error(404, "Permiso Denegado",
						"No tiene permisos para acceder a esa URL."));
				return false;
			}
			return true;
		} catch (Exception e) {
			logger.log("Se produjo una excepcion: " + e.getMessage(), 2);
			return false;
		}

	}

	/**
	 * seleccionarOperacion
	 * 
	 * @param parametros
	 *            Hashtable
	 * @return int
	 */
	private int seleccionarOperacion(Hashtable<Object, Object> parametros) {
		if (parametros.get("operacion").toString().toUpperCase().startsWith(
				"EMITIR")) {
			if (parametros.get("tipo").toString().toUpperCase().startsWith(
					"CLASE2")) {
				return OPE_EMITIR_C2;
			} else {
				return OPE_EMITIR_C1;
			}
		}
		if (parametros.get("operacion").toString().toUpperCase().startsWith(
				"BUSCAR")) {
			return OPE_BUSCAR;
		}
		if (parametros.get("operacion").toString().toUpperCase().startsWith(
				"REVOCAR")) {
			return OPE_REVOCAR;
		}
		if (parametros.get("operacion").toString().toUpperCase().startsWith(
				"SUSPENDER")) {
			return OPE_SUSPENDER;
		}
		if (parametros.get("operacion").toString().toUpperCase().startsWith(
				"RENOVAR")) {
			return OPE_RENOVAR;
		}
		if (parametros.get("operacion").toString().toUpperCase().startsWith(
				"DESCARGAR")) {
			return OPE_DESCARGAR;
		} else {
			return -1;
		}
	}

	private boolean usingPost(String[] inputs) {
		return (inputs[0].toUpperCase().startsWith("POST"));
	}

	private void readPostData(String[] inputs, int i, DataInputStream in)
			throws IOException {
		int contentLength = contentLength(inputs);
		byte[] postData = new byte[contentLength];
		in.read(postData);
		// Mirar esto, por eso no te coge los acentos
		inputs[++i] = new String(postData, 0);
	}

	private int contentLength(String[] inputs) {
		String input;
		for (int i = 0; i < inputs.length; i++) {
			if (inputs[i].length() == 0) {
				break;
			}
			input = inputs[i].toUpperCase();
			if (input.startsWith("CONTENT-LENGTH")) {
				return (getLength(input));
			}
		}
		return (0);
	}

	private int getLength(String length) {
		StringTokenizer tok = new StringTokenizer(length);
		tok.nextToken();
		return (Integer.parseInt(tok.nextToken()));
	}

	/**
	 * emitir
	 * 
	 * @param parametros
	 *            Hashtable
	 * @param sOut
	 *            OutputStream
	 */
	private void emitirClase1(Hashtable<Object, Object> parametros,
			OutputStream sOut) {
		String fich = null;
		File f = null;
		InputStream sin = null;
		X509Certificate cert = null;
		int tipo = 0;
		String navegador = "";
		String CN = "";
		String E = "";
		String C = "";
		String S = "";
		String L = "";
		String CH = "";
		String PK = "";
		String csr = "";

		if (parametros.containsKey("CN")) {
			CN = parametros.get("CN").toString();
		}
		if (parametros.containsKey("E")) {
			E = parametros.get("E").toString();
		}
		if (parametros.containsKey("C")) {
			C = parametros.get("C").toString();
		}
		if (parametros.containsKey("S")) {
			S = parametros.get("S").toString();
		}
		if (parametros.containsKey("L")) {
			L = parametros.get("L").toString();
		}
		if (parametros.containsKey("CH1")) {
			CH = parametros.get("CH1").toString();
		}
		if (parametros.containsKey("public_key")) {
			PK = parametros.get("public_key").toString();
		}

		if (parametros.containsKey("csr")) {
			csr = parametros.get("csr").toString();
		}

		if (parametros.containsKey("operacion")) {
			navegador = parametros.get("operacion").toString().split("_")[1];
			if (parametros.get("operacion").toString().split("_")[2]
					.compareToIgnoreCase("cp") == 0) {
				tipo = 0;
			} else {
				tipo = 1;
			}
		}

		if (tipo == 0) {
			logger.log(
					"Peticion recibida: <operacion=Emitir Certificado Personal Clase 1,CN="
							+ CN + ",E=" + E + ",C=" + C + ",S=" + S + ",L="
							+ L + "> Procesando", 0);
			cert = ra.emitirCP(CN, E, C, S, L, CH, PK, storePassword,
					keyPassword, navegador, 1);
		} else {
			logger
					.log(
							"Peticion recibida: <operacion=Emitir Certificado Servidor Web Seguro Clase 1,CN="
									+ CN + ",E=" + E + "> Procesando", 0);
			cert = ra.emitirSSL(CN, E, CH, csr, storePassword, keyPassword, 1);
		}

		try {
			if (cert == null) {
				logger.log(ra.getLastError().replaceAll("\n", ""), 2);
				error("error.htm", ra.getLastError(), sOut);
			} else {

				fich = ConfigManager.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/html/" + "C1_instalar.htm";
				f = new File(fich);
				if (comprobarFichero(fich, f, sOut)) {
					sin = new FileInputStream(f);
					String cabmime = HttpUtilidades.mimeTypeString(fich);
					int n = sin.available();
					sOut.write(HttpUtilidades.cabMime(cabmime, n));
					byte buf[] = new byte[buffer];
					while ((n = sin.read(buf)) >= 0) {
						sOut.write(buf, 0, n);

					}

					sin.close();
					logger.log("Certificado Clase 1 emitido: <dn="
							+ cert.getSubjectDN().toString() + ">", 0);
				}

			}
		} catch (Exception ex) {
			logger.log(ra.getLastError().replaceAll("\n", ""), 2);
			error("error.htm", ra.getLastError(), sOut);
		}
	}

}
