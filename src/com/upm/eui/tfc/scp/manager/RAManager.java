package com.upm.eui.tfc.scp.manager;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.bouncycastle.util.encoders.Hex;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import com.upm.eui.tfc.scp.excep.CAManagerException;
import com.upm.eui.tfc.scp.utiles.DigestType;
import com.upm.eui.tfc.scp.utiles.DigestUtil;

/**
 * Clase encargada de implementar la Autoridad de Registro. Es la encargada de
 * comunicarse la clase que implementa la Autoridad de Certificacion (solo esta
 * clase tiene acceso directo por motivos de seguridad). Entre sus funciones
 * estan, ofrecer metodos al cliente HTTP para las distintas operaciones
 * ofrecidas a traves del interfaz web (emision, renovacion, revocacion...) Es
 * ademas la encargada de registrar y autorizar la emision de certificados
 * digitales. Tambien gestiona el directorio publico de certificados de la CA.
 * 
 * @version 1.0
 */

public class RAManager {

	private CAManager ca = null;
	private String lastError = "";
	final static private String verde = "<font color='#008000'>";
	final static private String rojo = "<font color='#FF0000'>";
	final static private String fin = "</font>";

	public RAManager() {
		ca = new CAManager();
	}

	public X509Certificate emitirCP(String sCommonName, String sEmailAddress,
			String sCountryCode, String sState, String sLocality,
			String Challenge, String pkB64, char[] storePassword,
			char[] keyPassword, String navegador, int clase) {

		BASE64Decoder dec = new BASE64Decoder();
		NetscapeCertRequest reqNS = null;
		PKCS10CertificationRequest reqMS = null;
		X509Certificate cert = null;
		String tempdn = "";
		boolean autorizado = false;
		boolean registrado = false;

		if (sCommonName.compareTo("") != 0) {
			tempdn = "CN=" + sCommonName;
		}

		if (sEmailAddress.compareTo("") != 0) {
			tempdn = tempdn + ",E=" + sEmailAddress;
		}

		if (sCountryCode.compareTo("") != 0) {
			tempdn = tempdn + ",C=" + sCountryCode;
		}

		if (sState.compareTo("") != 0) {
			tempdn = tempdn + ",ST=" + sState;
		}

		if (sLocality.compareTo("") != 0) {
			tempdn = tempdn + ",L=" + sLocality;
		}

		if (Challenge.compareTo("") != 0) {
			tempdn = tempdn + ",OU=" + Challenge;
		}

		try {

			if (comprobarDN(sCommonName, sEmailAddress, 0, clase)) {

				if (clase == 1) {
					autorizado = true;
				} else {
					autorizado = RAautorizar(sCommonName, sEmailAddress,
							sCountryCode, sState, sLocality, 0);
				}
				if (autorizado) {

					// Monto el PKCS10
					if (navegador.compareToIgnoreCase("MS") == 0) {
						reqMS = new PKCS10CertificationRequest(dec
								.decodeBuffer(pkB64));
						if ((reqMS.verify())
								&& (reqMS.getCertificationRequestInfo()
										.getSubject().toString().compareTo(
												tempdn) == 0)) {
							cert = ca
									.emitirCP(
											sCommonName,
											sEmailAddress,
											sCountryCode,
											sState,
											sLocality,
											reqMS.getPublicKey(),
											Integer
													.parseInt(ConfigManager
															.obtenerParametro("CA/EMISION/VALIDEZ/CLASE"
																	+ clase
																	+ "/CP")),
											storePassword, keyPassword, clase);
						} else {
							lastError = "Error al validar la CSR (Certificate Signing Request). Los datos firmados no corresponden con los datos del formulario. \nNo se emitio su certificado.";
							return null;
						}
					} else {
						reqNS = new NetscapeCertRequest(dec.decodeBuffer(pkB64));
						cert = ca
								.emitirCP(
										sCommonName,
										sEmailAddress,
										sCountryCode,
										sState,
										sLocality,
										reqNS.getPublicKey(),
										Integer
												.parseInt(ConfigManager
														.obtenerParametro("CA/EMISION/VALIDEZ/CLASE"
																+ clase + "/CP")),
										storePassword, keyPassword, clase);
					}
					if (cert == null) {
						lastError = "Error en la CA al emitir el certificado. \nNo se emitio su certificado.";
						return null;
					} else {
						if (clase == 2) {
							if (publicarCertWeb(cert, sCommonName,
									sEmailAddress, sCountryCode, sState,
									sLocality, Challenge, 0, clase)
									&& registroInterno(cert, sCommonName,
											sEmailAddress, sCountryCode,
											sState, sLocality, Challenge, 0,
											clase)) {

								if (RAregistrar(cert, sCommonName,
										sEmailAddress, sCountryCode, sState,
										sLocality, 0)) {
									return cert;
								} else {
									lastError = "Error al registrar el certificado en el repositorio. \nNo se emitio su certificado.";
									return null;
								}
							} else {
								lastError = "Error al publicar en la web el certificado. \nNo se emitio su certificado.";
								return null;
							}

						} else {
							if (registroInterno(cert, sCommonName,
									sEmailAddress, "", "", "", Challenge, 1,
									clase)) {
								registrado = true;
								SMTPManager smtp = new SMTPManager();
								if (smtp.enviarCP(cert, sCommonName,
										sEmailAddress, null, Challenge)) {
									return cert;
								} else {
									quitarRegistroInterno(cert, sCommonName,
											sEmailAddress, 0);
									lastError = "Error al enviar el correo electronico a la direccion: "
											+ sEmailAddress
											+ ". \nNo se emitio su certificado.";
									return null;
								}
							} else {
								lastError = "Error al realizar el registro interno del certificado. \nNo se emitio su certificado.";
								return null;
							}
						}

					}
				} else {
					lastError = "La RA ha denegado la peticion del certificado. Si el error persiste contacte con el administrador del sistema.";
					return null;
				}

			} else {
				lastError = "Los datos que a introducido ya existen en este Sistema de Certificacion Publico."
						+ "\n\nSi esta solicitando un certificado personal eliga otro \"Correo electronica\"."
						+ "\nSi esta solicitando un certificado de servidor seguro eligar otra \"Nombre de sitio web\".";
				return null;
			}
		} catch (IOException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 0);
			}
			lastError = "Error al acceder a los ficheros de configuracion XML. No se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (org.jdom.JDOMException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 0);
			}
			lastError = "Error al acceder a los ficheros de configuracion XML. No se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (NoSuchAlgorithmException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 0);
			}
			lastError = "Error al intentar construir el CSR (Certificate Signin Request). Problemas con el algoritmo. \nNo se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (NoSuchProviderException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 0);
			}
			lastError = "Error al intentar construir el CSR (Certificate Signin Request). Problemas con el proveedor. \nNo se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (InvalidKeyException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 0);
			}
			lastError = "Error al intentar construir el CSR (Certificate Signin Request). Problemas con la clave. \nNo se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (SignatureException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 0);
			}
			lastError = "Error al intentar construir el CSR (Certificate Signin Request). Problemas con la firma. \nNo se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (CAManagerException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 0);
			}
			lastError = "Error al intentar procesar la peticion. \nMensaje de la CA:\n\n"
					+ ex.getMessage();
			return null;
		} catch (IllegalArgumentException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 0);
			}
			lastError = "Argumentos errones. Alguno de los argumentos facilitados no tiene formato correcto.";
			return null;
		} catch (Exception ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 0);
			}
			lastError = "Se produjo un eror. \nMensaje del error: "
					+ ex.getMessage();
			return null;
		}

	}

	/**
	 * quitarRegistroInterno
	 * 
	 * @param cert
	 *            X509Certificate
	 * @param sCommonName
	 *            String
	 * @param sEmailAddress
	 *            String
	 * @param string
	 *            String
	 * @param string1
	 *            String
	 * @param string2
	 *            String
	 * @param Challenge
	 *            String
	 * @param i
	 *            int
	 * @param clase
	 *            int
	 */
	private void quitarRegistroInterno(X509Certificate cert, String CN,
			String E, int tipo) {
		Element aux = null;
		File f1 = null;
		SAXBuilder builder1 = new SAXBuilder();
		Document reg1 = null;
		Document reg2 = null;
		File f2 = null;
		XMLOutputter out = new XMLOutputter();
		Object[] tabla = null;
		List emitidos = null;

		try {
			f1 = new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/data/" + "emitidosC1.xml");
			if (tipo == 0) {
				f2 = new File(ConfigManager
						.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/data/" + "pendientes.xml");
			}

			if (f1.exists() && (f2.exists() || tipo == 1)) {

				reg1 = builder1.build(f1);
				if (tipo == 0) {
					reg2 = builder1.build(f2);
				}

				emitidos = reg1.getRootElement().getChildren();
				tabla = emitidos.toArray();
				for (int i = 0; i < tabla.length; i++) {
					aux = (Element) tabla[i];
					if ((aux.getChild("CN").getText().compareToIgnoreCase(CN) == 0)
							&& (aux.getChild("EMAIL").getText()
									.compareToIgnoreCase(E) == 0)) {
						reg1.getRootElement().removeChild(aux);
						out.output(reg1, new FileOutputStream(f1));
					}
				}

				if (tipo == 0) {
					emitidos = reg2.getRootElement().getChildren();
					tabla = emitidos.toArray();
					for (int i = 0; i < tabla.length; i++) {
						aux = (Element) tabla[i];
						if (aux.getChild("PIN").getText().compareToIgnoreCase(
								DigestUtil.getMessageDigest(cert.getEncoded(),
										DigestType.MD5)) == 0) {
							reg2.getRootElement().removeChild(aux);
							out.output(reg2, new FileOutputStream(f2));
						}
					}
				}

			}
		} catch (Exception ex) {

		}
	}

	/**
	 * registrar
	 * 
	 * @param cert
	 *            X509Certificate
	 * @param sCommonName
	 *            String
	 * @param sEmailAddress
	 *            String
	 * @param sCountryCode
	 *            String
	 * @param sState
	 *            String
	 * @param sLocality
	 *            String
	 * @param Challenge
	 *            String
	 * @param i
	 *            int
	 * @return boolean
	 */
	private boolean RAregistrar(X509Certificate cert, String CN, String E,
			String C, String S, String L, int tipo) {
		String modo = "";

		try {
			if (ConfigManager.obtenerParametro("RA/AUTORIZACION/ACTIVADO")
					.compareToIgnoreCase("SI") == 0) {
				modo = ConfigManager.obtenerParametro("RA/AUTORIZACION/MODO");
				if (modo.compareToIgnoreCase("LDAP") == 0) {
					return RAregistrarLDAP(cert, CN, E, C, S, L, tipo);
				} else {
					return RAregistrarFICHERO(cert, CN, E, C, S, L, tipo);
				}
			} else {
				return true;
			}
		} catch (Exception ex) {
			return false;
		}
	}

	/**
	 * RAregistrarFICHERO
	 * 
	 * @param cert
	 *            X509Certificate
	 * @param CN
	 *            String
	 * @param E
	 *            String
	 * @param C
	 *            String
	 * @param S
	 *            String
	 * @param L
	 *            String
	 * @param tipo
	 *            int
	 * @return boolean
	 */
	private boolean RAregistrarFICHERO(X509Certificate cert, String CN,
			String E, String C, String S, String L, int tipo) {
		File f = null;
		SAXBuilder builder = new SAXBuilder();
		Document doc = null;
		XMLOutputter out = new XMLOutputter();
		FileOutputStream fos = null;
		Element aux = null;
		BASE64Encoder enc = new BASE64Encoder();
		String fichero = "";

		try {

			if (tipo == 0) {
				fichero = ConfigManager
						.obtenerParametro("RA/REGISTRO/FICHEROS/FICHEROCP");
			} else {
				fichero = ConfigManager
						.obtenerParametro("RA/REGISTRO/FICHEROS/FICHEROSSL");
			}

			f = new File(fichero);

			if (!f.exists()) {
				fos = new FileOutputStream(f);
				fos
						.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?><REGISTRO />"
								.getBytes());
				fos.close();
			}

			doc = builder.build(f);
			aux = new Element("CERTIFICADO");

			if (ConfigManager.obtenerParametro("RA/REGISTRO/FICHEROS/CN")
					.compareToIgnoreCase("S") == 0) {
				aux.addContent(new Element("CN").setText(CN));
			}

			if (ConfigManager.obtenerParametro("RA/REGISTRO/FICHEROS/E")
					.compareToIgnoreCase("S") == 0) {
				aux.addContent(new Element("E").setText(E));
			}

			if (ConfigManager.obtenerParametro("RA/REGISTRO/FICHEROS/C")
					.compareToIgnoreCase("S") == 0) {
				aux.addContent(new Element("C").setText(C));
			}

			if (ConfigManager.obtenerParametro("RA/REGISTRO/FICHEROS/S")
					.compareToIgnoreCase("S") == 0) {
				aux.addContent(new Element("S").setText(S));
			}

			if (ConfigManager.obtenerParametro("RA/REGISTRO/FICHEROS/L")
					.compareToIgnoreCase("S") == 0) {
				aux.addContent(new Element("L").setText(L));
			}

			if (ConfigManager.obtenerParametro("RA/REGISTRO/FICHEROS/DN")
					.compareToIgnoreCase("S") == 0) {
				aux.addContent(new Element("DN").setText(cert.getSubjectDN()
						.toString()));
			}

			if (ConfigManager.obtenerParametro("RA/REGISTRO/FICHEROS/CERT")
					.compareToIgnoreCase("S") == 0) {
				aux.addContent(new Element("CERT").setText(enc.encode(cert
						.getEncoded())));
			}

			doc.getRootElement().addContent(aux);
			out.output(doc, new FileOutputStream(fichero));

			return true;

		} catch (Exception ex) {
			return false;
		}
	}

	/**
	 * RAregistrarLDAP
	 * 
	 * @param cert
	 *            X509Certificate
	 * @param CN
	 *            String
	 * @param E
	 *            String
	 * @param C
	 *            String
	 * @param S
	 *            String
	 * @param L
	 *            String
	 * @param tipo
	 *            int
	 * @return boolean
	 */
	private boolean RAregistrarLDAP(X509Certificate cert, String CN, String E,
			String C, String S, String L, int tipo) {
		return false;
	}

	public X509Certificate emitirSSL(String sCommonName, String sEmailAddress,
			String Challenge, String csr, char[] storePassword,
			char[] keyPassword, int clase) {

		PKCS10CertificationRequest reqMS = null;
		X509Certificate cert = null;
		String aux = "";
		boolean autorizado = false;
		boolean registrado = false;

		try {

			// Accedo al fichero de propiedades para ver la validez de los
			// certificados

			if (comprobarDN(sCommonName, sEmailAddress, 1, clase)) {

				if (clase == 1) {
					autorizado = true;
				} else {
					autorizado = RAautorizar(sCommonName, sEmailAddress, "",
							"", "", 1);
				}

				if (autorizado) {

					// Monto el PKCS10

					reqMS = new PKCS10CertificationRequest(PEMtoDER(csr
							.getBytes()));
					// aux = reqMS.getCertificationRequestInfo().getSubject()
					// .toString().split(",")[0].split("=")[1];
					String[] subject = reqMS.getCertificationRequestInfo()
							.getSubject().toString().split(",");

					for (int i = 0; i < subject.length; i++) {
						if (subject[i].startsWith("CN=")) {
							aux = subject[i].split("=")[1];
							break;
						}
					}
					if (aux.compareTo(sCommonName) == 0) {
						cert = ca
								.emitirSSL(
										reqMS.getCertificationRequestInfo()
												.getSubject().toString(),
										reqMS.getPublicKey(),
										Integer
												.parseInt(ConfigManager
														.obtenerParametro("CA/EMISION/VALIDEZ/CLASE"
																+ clase
																+ "/SSL")),
										storePassword, keyPassword, clase);
					}else{
						lastError = "Error en la peticion. No coincide el nombre de dominio introducido en el formulario con el incluido en la peticion firmadad de certificado (CSR).";
						return null;
					}

					if (cert == null) {
						lastError = "Error en la CA al emitir el certificado. \nNo se emitio su certificado.";
						return null;
					} else {
						if (clase == 2) {
							if (publicarCertWeb(cert, sCommonName,
									sEmailAddress, "", "", "", Challenge, 1,
									clase)
									&& registroInterno(cert, sCommonName,
											sEmailAddress, "", "", "",
											Challenge, 1, clase)) {
								if (RAregistrar(cert, sCommonName,
										sEmailAddress, "", "", "", 1)) {
									return cert;
								} else {
									lastError = "Error al registrar el certificado en el repositorio. \nNo se emitio su certificado.";
									return null;
								}
							} else {
								lastError = "Error al publicar en la web el certificado. \nNo se emitio su certificado.";
								return null;
							}
						} else {

							if (registroInterno(cert, sCommonName,
									sEmailAddress, "", "", "", Challenge, 1,
									clase)) {
								registrado = true;
								SMTPManager smtp = new SMTPManager();
								if (smtp.enviarSSL(cert, sCommonName,
										sEmailAddress, null)) {
									return cert;
								} else {
									quitarRegistroInterno(cert, sCommonName,
											sEmailAddress, 1);
									lastError = "Error al enviar el correo electronico a la direccion: "
											+ sEmailAddress
											+ ". \nNo se emitio su certificado.";
									return null;
								}
							} else {
								lastError = "Error al realizar el registro interno del certificado. \nNo se emitio su certificado.";
								return null;
							}
						}
					}
				} else {
					lastError = "La RA ha denegado la peticion del certificado. Si el error persiste contacte con el administrador del sistema.";
					return null;
				}

			} else {
				lastError = "Los datos que a introducido ya existen en este Sistema de Certificacion Publico."
						+ "\n\nSi esta solicitando un certificado personal eliga otro \"Correo electronica\"."
						+ "\nSi esta solicitando un certificado de servidor seguro eligar otra \"Nombre de sitio web\".";

				return null;
			}
		} catch (IOException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 1);
			}
			lastError = "Error al acceder a los ficheros de configuracion XML. No se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (org.jdom.JDOMException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 1);
			}
			lastError = "Error al acceder a los ficheros de configuracion XML. No se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (NoSuchAlgorithmException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 1);
			}
			lastError = "Error al intentar construir el CSR (Certificate Signin Request). No se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (NoSuchProviderException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 1);
			}
			lastError = "Error al intentar construir el CSR (Certificate Signin Request). Problemas con el proveedor. \nNo se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (InvalidKeyException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 1);
			}
			lastError = "Error al intentar construir el CSR (Certificate Signin Request). Problemas con la clave. \nNo se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (CAManagerException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 1);
			}
			lastError = "Error al intentar procesar la peticion. \nMensaje de la CA:\n\n"
					+ ex.getMessage();
			return null;
		} catch (IllegalArgumentException ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 1);
			}
			lastError = "Argumentos errones. Alguno de los argumentos facilitados no tiene formato correcto.";
			return null;
		} catch (Exception ex) {
			if (registrado) {
				quitarRegistroInterno(cert, sCommonName, sEmailAddress, 1);
			}
			lastError = "Se produjo un error. \nMensaje del error: "
					+ ex.getMessage();
			return null;
		}
	}

	/**
	 * registroInternoC1
	 * 
	 * @param cert
	 *            X509Certificate
	 * @param sCommonName
	 *            String
	 * @param sEmailAddress
	 *            String
	 * @param string
	 *            String
	 * @param string1
	 *            String
	 * @param string2
	 *            String
	 * @param Challenge
	 *            String
	 * @param i
	 *            int
	 * @param clase
	 *            int
	 * @return boolean
	 */
	private boolean publicarCertWeb(X509Certificate cert, String CN, String E,
			String C, String ST, String L, String Challenge, int tipo, int clase) {
		FileOutputStream fos = null;
		String filename = "";

		try {

			filename = DigestUtil.getMessageDigest(cert.getEncoded(),
					DigestType.MD5).replace(':', '_')
					+ ".cer";

			// Guardar el .cer en el repositorio
			fos = new FileOutputStream(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/html/Repositorio/" + filename);
			fos.write(cert.getEncoded());
			fos.close();

			// Añadir al XML del repositorio
			SAXBuilder builder = new SAXBuilder();
			Document doc = builder.build(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/html/" + "directorio.xml");

			XMLOutputter fmt = new XMLOutputter();

			Element certificados = doc.getRootElement();
			Element ecert = new Element("CERTIFICADO");
			Element desde = new Element("DESDE");
			Element hasta = new Element("HASTA");
			Element fichero = new Element("FICHERO");
			Element email = new Element("EMAIL");
			Element nomyape = new Element("CN");

			desde.setText(cert.getNotBefore().toString());
			hasta.setText(cert.getNotAfter().toString());
			email.setText(E);
			fichero.setText(filename);
			nomyape.setText(CN);

			ecert.addContent(desde);
			ecert.addContent(hasta);

			if (tipo == 0) {
				ecert.addContent(email);
			}

			ecert.addContent(fichero);
			ecert.addContent(nomyape);

			if (tipo == 0) {
				ecert.addContent(new Element("TIPO").setText("CP"));
			} else {
				ecert.addContent(new Element("TIPO").setText("SSL"));
			}
			ecert.addContent(new Element("CLASE")
					.setText(String.valueOf(clase)));
			certificados.addContent(ecert);
			fmt.output(doc, new FileOutputStream(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/html/" + "directorio.xml"));
			return true;
		} catch (Exception ex) {
			return false;
		}
	}

	/**
	 * validarPeticion
	 * 
	 * @param CN
	 *            String
	 * @param E
	 *            String
	 * @param C
	 *            String
	 * @param ST
	 *            String
	 * @param L
	 *            String
	 * @return boolean
	 */
	private boolean RAautorizar(String CN, String E, String C, String ST,
			String L, int tipo) {
		String modo = "";

		try {
			if (ConfigManager.obtenerParametro("RA/AUTORIZACION/ACTIVADO")
					.compareToIgnoreCase("SI") == 0) {
				modo = ConfigManager.obtenerParametro("RA/AUTORIZACION/MODO");
				if (modo.compareToIgnoreCase("LDAP") == 0) {
					return RAautorizarLDAP(CN, E, C, ST, L, tipo);
				} else {
					return RAautorizarFICHERO(CN, E, C, ST, L, tipo);
				}
			} else {
				return true;
			}
		} catch (Exception ex) {
			return false;
		}
	}

	/**
	 * RAautorizarFICHERO
	 * 
	 * @param CN
	 *            String
	 * @param E
	 *            String
	 * @param C
	 *            String
	 * @param ST
	 *            String
	 * @param L
	 *            String
	 * @param tipo
	 *            int
	 */
	private boolean RAautorizarFICHERO(String CN, String E, String C, String S,
			String L, int tipo) {
		File f = null;
		int iCN = 0;
		int iE = 0;
		int iC = 0;
		int iS = 0;
		int iL = 0;
		String separador = "";
		FileReader fr = null;
		BufferedReader br = null;
		String linea = "";
		boolean encontrado;
		int usados;
		int validados;

		try {
			if (tipo == 0) {
				f = new File(ConfigManager
						.obtenerParametro("RA/AUTORIZACION/FICHEROS/FICHEROCP"));
			} else {
				f = new File(
						ConfigManager
								.obtenerParametro("RA/AUTORIZACION/FICHEROS/FICHEROSSL"));
			}

			if (!f.exists()) {
				return false;
			} else {
				iCN = Integer.parseInt(ConfigManager
						.obtenerParametro("RA/AUTORIZACION/FICHEROS/CN"));
				iE = Integer.parseInt(ConfigManager
						.obtenerParametro("RA/AUTORIZACION/FICHEROS/E"));
				iC = Integer.parseInt(ConfigManager
						.obtenerParametro("RA/AUTORIZACION/FICHEROS/C"));
				iS = Integer.parseInt(ConfigManager
						.obtenerParametro("RA/AUTORIZACION/FICHEROS/S"));
				iL = Integer.parseInt(ConfigManager
						.obtenerParametro("RA/AUTORIZACION/FICHEROS/L"));

				separador = ConfigManager
						.obtenerParametro("RA/AUTORIZACION/FICHEROS/SEPARADOR");

				fr = new FileReader(f);
				br = new BufferedReader(fr);

				encontrado = false;
				while (((linea = br.readLine()) != null) && (!encontrado)) {

					if (!linea.startsWith("#") && !(linea.length() == 0)) {
						usados = 0;
						validados = 0;

						if (iCN > 0) {
							usados++;
							if (linea.split(separador)[iCN - 1].compareTo(CN) == 0) {
								validados++;
							}
						}
						if (iE > 0) {
							usados++;
							if (linea.split(separador)[iE - 1].compareTo(E) == 0) {
								validados++;
							}
						}
						if (iC > 0) {
							usados++;
							if (linea.split(separador)[iC - 1].compareTo(C) == 0) {
								validados++;
							}
						}
						if (iS > 0) {
							usados++;
							if (linea.split(separador)[iS - 1].compareTo(S) == 0) {
								validados++;
							}
						}
						if (iL > 0) {
							usados++;
							if (linea.split(separador)[iL - 1].compareTo(L) == 0) {
								validados++;
							}
						}

						if ((usados == validados) && (usados > 0)) {
							encontrado = true;
						}
					}
				}
				return encontrado;
			}
		} catch (Exception ex) {
			return false;
		}
	}

	/**
	 * RAautorizarLDAP
	 * 
	 * @param CN
	 *            String
	 * @param E
	 *            String
	 * @param C
	 *            String
	 * @param ST
	 *            String
	 * @param L
	 *            String
	 * @param tipo
	 *            int
	 */
	private boolean RAautorizarLDAP(String CN, String E, String C, String ST,
			String L, int tipo) {
		return true;
	}

	/**
	 * comprobarDN
	 * 
	 * @param string
	 *            String
	 * @param sEmailAddress
	 *            String
	 * @param sCountryCode
	 *            String
	 * @param sState
	 *            String
	 * @param sLocality
	 *            String
	 * @return boolean
	 */
	private boolean comprobarDN(String CN, String E, int tipo, int clase) {
		Element aux = null;
		File f = null;
		SAXBuilder builder = new SAXBuilder();
		Document reg = null;
		FileOutputStream fos = null;

		try {
			// Guardar en el ra.ks
			if (clase == 2) {
				f = new File(ConfigManager
						.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/data/" + "emitidosC2.xml");
			} else {
				f = new File(ConfigManager
						.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/data/" + "emitidosC1.xml");
			}

			if (!f.exists()) {
				if (f.createNewFile()) {
					fos = new FileOutputStream(f);
					fos
							.write("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><EMITIDOS />"
									.getBytes());
					fos.close();
					return true;
				} else {
					return false;
				}
			} else {
				if (clase == 2) {
					reg = builder.build(ConfigManager
							.obtenerParametro("INSTALACION/DIRECTORIO")
							+ "/data/" + "emitidosC2.xml");
				} else {
					reg = builder.build(ConfigManager
							.obtenerParametro("INSTALACION/DIRECTORIO")
							+ "/data/" + "emitidosC1.xml");
				}

				List emitidos = reg.getRootElement().getChildren();
				Object[] tabla = emitidos.toArray();
				for (int i = 0; i < tabla.length; i++) {
					aux = (Element) tabla[i];
					if ((aux.getChild("CN").getText().compareToIgnoreCase(CN) == 0)
							&& (tipo == 1)) {
						return false;
					}
					if ((aux.getChild("EMAIL").getText().compareToIgnoreCase(E) == 0)
							&& (tipo == 0)) {
						return false;
					}

				}
				return true;
			}
		} catch (Exception ex) {
			return false;
		}
	}

	public String validar(char[] password, X509Certificate cert) {
		String aux = "";

		aux = ca.validar(password, cert);

		if (aux.compareToIgnoreCase("VALIDO") == 0) {
			return verde + aux + fin;
		} else {
			return rojo + aux + fin;
		}
	}

	public String invertirCadena(String cadena) {
		return ca.invertirCadena(cadena);
	}

	public String getLastError() {
		return lastError;
	}

	/**
	 * buscar
	 * 
	 * @param CN
	 *            String
	 * @param E
	 *            String
	 * @param serial
	 *            String
	 * @return X509Certificate
	 */
	public Object[] buscar(String CN, String E, String tipo) {
		Element aux = null;
		Object[] retorno = new Object[7];

		if ((CN.compareTo("") == 0) && (E.compareTo("") != 0)) {
			tipo = "0";
		}

		if ((CN.compareTo("") != 0) && (E.compareTo("") == 0)) {
			tipo = "1";
		}

		try {
			// Guardar en el ra.ks
			File f = new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/data/" + "emitidosC2.xml");
			if (!f.exists()) {
				return null;
			} else {
				SAXBuilder builder = new SAXBuilder();
				Document reg = builder.build(ConfigManager
						.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/data/" + "emitidosC2.xml");
				List emitidos = reg.getRootElement().getChildren();
				Object[] tabla = emitidos.toArray();
				if (CN.compareTo("") != 0 || E.compareTo("") != 0) {
					for (int i = 0; i < tabla.length; i++) {
						aux = (Element) tabla[i];
						if (((aux.getChild("CN").getText().compareToIgnoreCase(
								CN) == 0) || (CN.compareToIgnoreCase("") == 0))
								&& ((aux.getChild("EMAIL").getText()
										.compareToIgnoreCase(E) == 0) || (E
										.compareToIgnoreCase("") == 0))
								&& ((aux.getChild("TIPO").getText()
										.compareToIgnoreCase(tipo) == 0) || (tipo
										.compareToIgnoreCase("") == 0))) {
							retorno[1] = (X509Certificate) CertificateFactory
									.getInstance("X.509")
									.generateCertificate(
											new FileInputStream(
													ConfigManager
															.obtenerParametro("INSTALACION/DIRECTORIO")
															+ "/html/Repositorio/"
															+ aux.getChild(
																	"FICHERO")
																	.getText()));
							retorno[0] = aux.getChild("FICHERO").getText();
							retorno[2] = aux.getChild("C").getText();
							retorno[3] = aux.getChild("S").getText();
							retorno[4] = aux.getChild("L").getText();
							retorno[5] = aux.getChild("EMAIL").getText();
							retorno[6] = aux.getChild("CN").getText();
							return retorno;
						}
					}
				}
				return null;
			}
		} catch (Exception ex) {
			return null;
		}
	}

	/**
	 * revocar
	 * 
	 * @param cert
	 *            X509Certificate
	 * @param password
	 *            char[]
	 */
	public boolean revocar(X509Certificate cert, char[] storePassword,
			char[] keyPassword, int motivo, String CN, String E,
			String Challenge) {
		Element aux = null;
		Element nuevo = null;
		Object[] tabla = null;
		String hash = "";
		String valido = "";
		valido = validar(storePassword, cert);
		if ((valido.compareToIgnoreCase(verde + "VALIDO" + fin) == 0)
				|| (valido.compareToIgnoreCase(rojo + "SUSPENDIDO" + fin) == 0)) {
			try {
				SAXBuilder builder = new SAXBuilder();
				Document reg = builder.build(ConfigManager
						.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/data/" + "emitidosC2.xml");
				Document rev = builder.build(ConfigManager
						.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/data/" + "revocados.xml");
				XMLOutputter out = new XMLOutputter();

				List emitidos = reg.getRootElement().getChildren();
				tabla = emitidos.toArray();
				for (int i = 0; i < tabla.length; i++) {
					aux = (Element) tabla[i];
					if (((aux.getChild("CN").getText().compareToIgnoreCase(CN) == 0) && (CN
							.compareToIgnoreCase("") != 0))
							|| ((aux.getChild("EMAIL").getText()
									.compareToIgnoreCase(E) == 0) && (E
									.compareToIgnoreCase("") != 0))) {
						hash = DigestUtil.getMessageDigest(
								Challenge.getBytes(), DigestType.MD5);
						if (hash.compareToIgnoreCase(aux.getChild("CHALLENGE")
								.getText()) == 0) {
							nuevo = new Element("CERTIFICADO");
						
							nuevo.addContent(new Element("SERIAL").setText(cert.getSerialNumber().toString()));
							nuevo.addContent(new Element("CHALLENGE")
									.setText(aux.getChild("CHALLENGE")
											.getText()));
							nuevo.addContent(new Element("EMAIL").setText(aux
									.getChild("EMAIL").getText()));
							nuevo.addContent(new Element("FICHERO").setText(aux
									.getChild("FICHERO").getText()));
							nuevo.addContent(new Element("CN").setText(aux
									.getChild("CN").getText()));
							nuevo.addContent(new Element("MOTIVO")
									.setText(String.valueOf(motivo)));
							rev.getRootElement().addContent(nuevo);
							out.output(rev, new FileOutputStream(ConfigManager
									.obtenerParametro("INSTALACION/DIRECTORIO")
									+ "/data/" + "revocados.xml"));
							return true;
						} else {
							lastError = "Contrase&ntilde;a incorrecta";
							return false;
						}
					}
				}
				lastError = "No existe un certificado con los datos facilitados";
				return false;
			} catch (Exception ex) {
				lastError = ex.getMessage();
				return false;
			}
		} else {
			lastError = "El certificado no es valido";
			return false;
		}
	}

	/**
	 * suspender
	 * 
	 * @param cert
	 *            X509Certificate
	 * @param password
	 *            char[]
	 */
	public boolean suspender(X509Certificate cert, char[] storePassword,
			char[] keyPassword, String accion, String CN, String E,
			String Challenge) {
		Element aux = null;
		Element nuevo = null;
		Object[] tabla = null;
		String hash = "";
		String valido = "";

		valido = validar(storePassword, cert);
		if ((valido.compareToIgnoreCase(verde + "VALIDO" + fin) == 0)
				|| ((valido.compareToIgnoreCase(rojo + "SUSPENDIDO" + fin) == 0))
				&& (accion.compareToIgnoreCase("V") == 0)) {
			try {
				SAXBuilder builder = new SAXBuilder();
				Document reg = builder.build(ConfigManager
						.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/data/" + "emitidosC2.xml");
				Document sus = builder.build(ConfigManager
						.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/data/" + "suspendidos.xml");
				XMLOutputter out = new XMLOutputter();

				List emitidos = reg.getRootElement().getChildren();
				tabla = emitidos.toArray();
				for (int i = 0; i < tabla.length; i++) {
					aux = (Element) tabla[i];
					if (((aux.getChild("CN").getText().compareToIgnoreCase(CN) == 0) && (CN
							.compareToIgnoreCase("") != 0))
							|| ((aux.getChild("EMAIL").getText()
									.compareToIgnoreCase(E) == 0) && (E
									.compareToIgnoreCase("") != 0))) {
						hash = DigestUtil.getMessageDigest(
								Challenge.getBytes(), DigestType.MD5);
						if (hash.compareToIgnoreCase(aux.getChild("CHALLENGE")
								.getText()) == 0) {
							if (accion.compareToIgnoreCase("Z") == 0) {
								ca.suspender(cert, storePassword, keyPassword);
								nuevo = new Element("CERTIFICADO");
								nuevo.addContent(new Element("SERIAL")
										.setText(cert.getSerialNumber().toString()));
								nuevo.addContent(new Element("CHALLENGE")
										.setText(aux.getChild("CHALLENGE")
												.getText()));
								nuevo.addContent(new Element("EMAIL")
										.setText(aux.getChild("EMAIL")
												.getText()));
								nuevo.addContent(new Element("FICHERO")
										.setText(aux.getChild("FICHERO")
												.getText()));
								nuevo.addContent(new Element("CN").setText(aux
										.getChild("CN").getText()));
								sus.getRootElement().addContent(nuevo);
								out
										.output(
												sus,
												new FileOutputStream(
														ConfigManager
																.obtenerParametro("INSTALACION/DIRECTORIO")
																+ "/data/"
																+ "suspendidos.xml"));
								return true;
							} else {
								emitidos = sus.getRootElement().getChildren();
								tabla = emitidos.toArray();
								for (i = 0; i < tabla.length; i++) {
									aux = (Element) tabla[i];
									if (((aux.getChild("CN").getText()
											.compareToIgnoreCase(CN) == 0) && (CN
											.compareToIgnoreCase("") != 0))
											|| ((aux.getChild("EMAIL")
													.getText()
													.compareToIgnoreCase(E) == 0) && (E
													.compareToIgnoreCase("") != 0))) {
										ca.reactivar(cert, storePassword,
												keyPassword);
										sus.getRootElement().removeChild(aux);
										out
												.output(
														sus,
														new FileOutputStream(
																ConfigManager
																		.obtenerParametro("INSTALACION/DIRECTORIO")
																		+ "/data/"
																		+ "suspendidos.xml"));

										return true;
									}
								}
								lastError = "El certificado que ha elegido para reactivar no estaba suspendido.";
								return false;
							}
						} else {
							lastError = "La contrase&ntilde;a que ha introducido es incorrecto. Si su problema persiste contacte con el Administrador del sistema.";
							return false;
						}
					}
				}
				lastError = "Error al buscar el certificado. No existe en este Sistema de certificacion ningun certificado con los datos que ha facilitado."
						+ "\n\nDatos de busqueda facilitados: \n\tCorreo Electronico -> "
						+ E + "\n\tNombre del sitio web -> " + CN;
				return false;
			} catch (Exception ex) {
				lastError = "Error, se produjo una excepcion y no se pudo completar la operacion. \nMensaje de la Excepcion: "
						+ ex.getMessage();
				return false;
			}

		} else {
			lastError = "El certificado no es valido. No se puede reactivar / suspender un certificado que no sea valido.";
			return false;
		}
	}

	/**
	 * inicializar
	 */
	public boolean inicializar(char[] storePassword, char[] keyPassword,
			String sCommonName, String sOrganisationUnit1,
			String sOrganisationUnit2, String sOrganisationUnit3,
			String sOrganisation, String sCountryCode, String Locality,
			String State, String Email, int iValidity, String keytype,
			int keylength, String sigtype) {
		Object[] retorno = new Object[3];
		FileOutputStream fos = null;
		String aux = "";
		X509Certificate cacert2 = null;
		X509Certificate cacert1 = null;
		X509CRL cacrl = null;

		try {
			retorno = ca.crearCA(storePassword, keyPassword, sCommonName,
					sOrganisationUnit1, sOrganisationUnit2, sOrganisationUnit3,
					sOrganisation, sCountryCode, Locality, State, Email,
					iValidity, keytype, keylength, sigtype);
			aux = ConfigManager.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/html/Repositorio/";
			cacert2 = (X509Certificate) retorno[0];
			cacert1 = (X509Certificate) retorno[2];
			cacrl = (X509CRL) retorno[1];

			fos = new FileOutputStream(aux + "cacertclase2.crt");
			fos.write(cacert2.getEncoded());
			fos.close();

			fos = new FileOutputStream(aux + "cacertclase1.crt");
			fos.write(cacert1.getEncoded());
			fos.close();

			fos = new FileOutputStream(aux + "ultimaCRL.crl");
			fos.write(cacrl.getEncoded());
			fos.close();

			// *********************************************
			// Registrar la CA y la CRL en LDAP o fichero XML

			// *********************************************
			// Pedir a la CA que genere el cert para SSL

			return true;

		} catch (Exception e) {
			lastError = "Error al inicializar la CA. No se pudo finalizar la operacion. \nMensaje de la excepcion: "
					+ e.getMessage();
			return false;
		}

	}

	public X509Certificate renovarCP(String sCommonName, String sEmailAddress,
			String sCountryCode, String sState, String sLocality,
			String Challenge, String pkB64, char[] storePassword,
			char[] keyPassword, String navegador) {
		BASE64Decoder dec = new BASE64Decoder();
		NetscapeCertRequest reqNS = null;
		PKCS10CertificationRequest reqMS = null;
		X509Certificate cert = null;
		String tempdn = "";

		if (sCommonName.compareTo("") != 0) {
			tempdn = "CN=" + sCommonName;
		}

		if (sEmailAddress.compareTo("") != 0) {
			tempdn = tempdn + ",E=" + sEmailAddress;
		}

		if (sCountryCode.compareTo("") != 0) {
			tempdn = tempdn + ",C=" + sCountryCode;
		}

		if (sState.compareTo("") != 0) {
			tempdn = tempdn + ",ST=" + sState;
		}

		if (sLocality.compareTo("") != 0) {
			tempdn = tempdn + ",L=" + sLocality;
		}

		if (Challenge.compareTo("") != 0) {
			tempdn = tempdn + ",OU=" + Challenge;
		}

		try {

			if (comprobarRenovacion(sCommonName, sEmailAddress, Challenge,
					storePassword)) {

				// Monto el PKCS10
				if (navegador.compareToIgnoreCase("MS") == 0) {
					reqMS = new PKCS10CertificationRequest(dec
							.decodeBuffer(pkB64));
					if ((reqMS.verify())
							&& (reqMS.getCertificationRequestInfo()
									.getSubject().toString().compareTo(tempdn) == 0)) {
						cert = ca
								.emitirCP(
										sCommonName,
										sEmailAddress,
										sCountryCode,
										sState,
										sLocality,
										reqMS.getPublicKey(),
										Integer
												.parseInt(ConfigManager
														.obtenerParametro("CA/RENOVACION/VALIDEZ/CP")),
										storePassword, keyPassword, 2);
					} else {
						lastError = "Error al validar la CSR (Certificate Signing Request). Los datos firmados no corresponden con los datos del formulario. \nNo se emitio su certificado.";
						return null;
					}
				} else {
					reqNS = new NetscapeCertRequest(dec.decodeBuffer(pkB64));
					cert = ca
							.emitirCP(
									sCommonName,
									sEmailAddress,
									sCountryCode,
									sState,
									sLocality,
									reqNS.getPublicKey(),
									Integer
											.parseInt(ConfigManager
													.obtenerParametro("CA/RENOVACION/VALIDEZ/CP")),
									storePassword, keyPassword, 2);
				}
				if (cert == null) {
					lastError = "Error en la CA al emitir el certificado. \nNo se renovo su certificado. \n"
							+ lastError;
					return null;
				} else {
					if (quitarAntiguo(sCommonName, sEmailAddress, 0)) {
						if (publicarCertWeb(cert, sCommonName, sEmailAddress,
								sCountryCode, sState, sLocality, Challenge, 0,
								2)) {
							if (registroInterno(cert, sCommonName,
									sEmailAddress, sCountryCode, sState,
									sLocality, Challenge, 0, 2)) {
								if (RAregistrar(cert, sCommonName,
										sEmailAddress, "", "", "", 1)) {
									return cert;
								} else {
									lastError = "Error al registrar el certificado en el repositorio. \nNo se emitio su certificado.";
									return null;
								}
							} else {
								lastError = "Error al realizar el registro interno del certificado. \nNo se emitio su certificado.";
								return null;
							}
						} else {
							lastError = "Error al publicar en el repositorio web el certificado. \nNo se emitio su certificado.";
							return null;
						}
					} else {
						lastError = "Error al retirar el certificado antiguo del repositorio web. \nNo se emitio su certificado.";
						return null;

					}
				}
			} else {
				return null;
			}
		} catch (IOException ex) {
			lastError = "Error al acceder a los ficheros de configuracion XML. No se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (org.jdom.JDOMException ex) {
			lastError = "Error al acceder a los ficheros de configuracion XML. No se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (NoSuchAlgorithmException ex) {
			lastError = "Error al intentar construir el CSR (Certificate Signin Request). Problemas con el algoritmo. \nNo se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (NoSuchProviderException ex) {
			lastError = "Error al intentar construir el CSR (Certificate Signin Request). Problemas con el proveedor. \nNo se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (InvalidKeyException ex) {
			lastError = "Error al intentar construir el CSR (Certificate Signin Request). Problemas con la clave. \nNo se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (SignatureException ex) {
			lastError = "Error al intentar construir el CSR (Certificate Signin Request). Problemas con la firma. \nNo se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (CAManagerException ex) {
			lastError = "Error al intentar procesar la peticion. \nMensaje de la CA:\n\n"
					+ ex.getMessage();
			return null;
		}
	}

	/**
	 * quitarAntiguo
	 * 
	 * @param cert
	 *            X509Certificate
	 * @param sCommonName
	 *            String
	 * @param sEmailAddress
	 *            String
	 * @param sCountryCode
	 *            String
	 * @param sState
	 *            String
	 * @param sLocality
	 *            String
	 * @param Challenge
	 *            String
	 * @param i
	 *            int
	 * @param i1
	 *            int
	 * @return boolean
	 */
	private boolean quitarAntiguo(String CN, String E, int tipo) {
		Element aux = null;
		File f = null;
		SAXBuilder builder = new SAXBuilder();
		Document reg = null;
		String stipo = "";
		XMLOutputter out = new XMLOutputter();
		File del = null;
		try {
			f = new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/html/directorio.xml");
			if (!f.exists()) {
				return false;
			} else {
				if (tipo == 0) {
					stipo = "CP";
				} else {
					stipo = "SSL";
				}
				reg = builder.build(ConfigManager
						.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/html/" + "directorio.xml");

				List emitidos = reg.getRootElement().getChildren();
				Object[] tabla = emitidos.toArray();
				for (int i = 0; i < tabla.length; i++) {
					aux = (Element) tabla[i];
					if ((aux.getChild("CN").getText().compareToIgnoreCase(CN) == 0)
							&& (aux.getChild("EMAIL").getText()
									.compareToIgnoreCase(E) == 0)
							&& (aux.getChild("TIPO").getText()
									.compareToIgnoreCase(stipo) == 0)) {
						del = new File(ConfigManager
								.obtenerParametro("INSTALACION/DIRECTORIO")
								+ "/html/Repositorio/"
								+ aux.getChild("FICHERO").getText());
						if (del.delete()) {
							reg.getRootElement().removeChild(aux);
							out.output(reg, new FileOutputStream(ConfigManager
									.obtenerParametro("INSTALACION/DIRECTORIO")
									+ "/html/directorio.xml"));
							return true;
						} else {
							return false;
						}
					}
				}
				return false;
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			return false;
		}
	}

	public X509Certificate renovarSSL(String sCommonName, String sEmailAddress,
			String Challenge, String csr, char[] storePassword,
			char[] keyPassword) {
		String aux = "";
		PKCS10CertificationRequest reqMS = null;
		X509Certificate cert = null;

		try {

			if (comprobarRenovacion(sCommonName, sEmailAddress, Challenge,
					storePassword)) {

				// Monto el PKCS10

				reqMS = new PKCS10CertificationRequest(PEMtoDER(csr.getBytes()));
				aux = reqMS.getCertificationRequestInfo().getSubject()
						.toString().split(",")[0].split("=")[1];
				if (aux.compareTo(sCommonName) == 0) {
					cert = ca
							.emitirSSL(
									reqMS.getCertificationRequestInfo()
											.getSubject().toString(),
									reqMS.getPublicKey(),
									Integer
											.parseInt(ConfigManager
													.obtenerParametro("CA/RENOVACION/VALIDEZ/SSL")),
									storePassword, keyPassword, 2);
				}

				if (cert == null) {
					lastError = "Error en la CA al emitir el certificado. \nNo se renovo su certificado.";
					return null;
				} else {
					if (quitarAntiguo(sCommonName, sEmailAddress, 1)) {
						if (publicarCertWeb(cert, sCommonName, sEmailAddress,
								"", "", "", Challenge, 1, 2)) {
							if (registroInterno(cert, sCommonName,
									sEmailAddress, "", "", "", Challenge, 1, 2)) {
								if (RAregistrar(cert, sCommonName,
										sEmailAddress, "", "", "", 1)) {
									return cert;
								} else {
									lastError = "Error al registrar el certificado en el repositorio. \nNo se emitio su certificado.";
									return null;
								}
							} else {
								lastError = "Error al realizar el registro interno del certificado. \nNo se emitio su certificado.";
								return null;
							}
						} else {
							lastError = "Error al publicar en el repositorio web el certificado. \nNo se emitio su certificado.";
							return null;
						}
					} else {
						lastError = "Error al retirar el certificado antiguo del repositorio web. \nNo se emitio su certificado.";
						return null;
					}

				}
			} else {
				lastError = "La contrase&ntilde;a que ha introducido es incorrecto. Si su problema persiste contacte con el Administrador del sistema.";
				return null;
			}
		} catch (IOException ex) {
			lastError = "Error al acceder a los ficheros de configuracion XML. No se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (org.jdom.JDOMException ex) {
			lastError = "Error al acceder a los ficheros de configuracion XML. No se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (NoSuchAlgorithmException ex) {
			lastError = "Error al intentar construir el CSR (Certificate Signin Request). Problemas con el algoritmo. \nNo se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (NoSuchProviderException ex) {
			lastError = "Error al intentar construir el CSR (Certificate Signin Request). Problemas con el proveedor. \nNo se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (InvalidKeyException ex) {
			lastError = "Error al intentar construir el CSR (Certificate Signin Request). Problemas con la clave. \nNo se pudo completar la operacion. \nExcepcion: "
					+ ex.getMessage();
			return null;
		} catch (CAManagerException ex) {
			lastError = "Error al intentar procesar la peticion. \nMensaje de la CA:\n\n"
					+ ex.getMessage();
			return null;
		}

	}

	/**
	 * comprobarRenovacion
	 * 
	 * @param sCommonName
	 *            String
	 * @param sEmailAddress
	 *            String
	 * @param Challenge
	 *            String
	 * @return boolean
	 */
	private boolean comprobarRenovacion(String CN, String E, String Challenge,
			char[] password) {
		Element aux = null;
		Object[] tabla = null;
		String hash = "";
		String valido = "";
		X509Certificate cert = null;

		try {
			SAXBuilder builder = new SAXBuilder();
			Document reg = builder.build(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/data/emitidosC2.xml");
			XMLOutputter out = new XMLOutputter();

			List emitidos = reg.getRootElement().getChildren();
			tabla = emitidos.toArray();
			for (int i = 0; i < tabla.length; i++) {
				aux = (Element) tabla[i];
				if (((aux.getChild("CN").getText().compareToIgnoreCase(CN) == 0) && (CN
						.compareToIgnoreCase("") != 0))
						|| ((aux.getChild("EMAIL").getText()
								.compareToIgnoreCase(E) == 0) && (E
								.compareToIgnoreCase("") != 0))) {
					hash = DigestUtil.getMessageDigest(Challenge.getBytes(),
							DigestType.MD5);
					if (hash.compareToIgnoreCase(aux.getChild("CHALLENGE")
							.getText()) == 0) {
						cert = (X509Certificate) CertificateFactory
								.getInstance("X.509")
								.generateCertificate(
										new FileInputStream(
												ConfigManager
														.obtenerParametro("INSTALACION/DIRECTORIO")
														+ "/html/Repositorio/"
														+ aux.getChild(
																"FICHERO")
																.getText()));
						valido = validar(password, cert);
						if (valido.compareToIgnoreCase(verde + "VALIDO" + fin) == 0) {
							if (((cert.getNotAfter().getTime() - System
									.currentTimeMillis()) / 1000) < (2678400)) {
								reg.getRootElement().removeChild(aux);
								out
										.output(
												reg,
												new FileOutputStream(
														ConfigManager
																.obtenerParametro("INSTALACION/DIRECTORIO")
																+ "/data/emitidosC2.xml"));
								return true;
							} else {
								lastError = "El certificado aun no se puede renovar. Puede renovar su certificado un mes antes de su fecha de caducidad.";
								return false;
							}
						} else {
							lastError = "El certificado que ha elegido no es valido";
							return false;
						}
					} else {
						lastError = "La contrase&ntilde;a que ha introducido es incorrecto. Si su problema persiste contacte con el Administrador del sistema.";
						return false;
					}
				}
			}
			lastError = "Error al buscar el certificado. No existe en este Sistema de certificacion ningun certificado con los datos que ha facilitado.";
			return false;

		} catch (Exception ex) {
			lastError = "Error, se produjo una excepcion y no se pudo completar la operacion. \nMensaje de la Excepcion: "
					+ ex.getMessage();
			return false;
		}

	}

	public static byte[] PEMtoDER(byte[] bytes) throws IOException {

		BufferedReader reader = new BufferedReader(new InputStreamReader(
				new ByteArrayInputStream(bytes)));
		String line = "";
		StringBuffer buf = new StringBuffer();
		// search for header
		while ((line = reader.readLine()) != null) {
			if (line.startsWith("-----")) {
				// found header
				while ((line = reader.readLine()) != null) {
					if (line.startsWith("-----")) {
						break; // found footer, end of data
					}
					buf.append(line);
				}
			}
		}
		return new BASE64Decoder().decodeBuffer(buf.toString());
	}

	private boolean registroInterno(X509Certificate cert, String CN, String E,
			String C, String ST, String L, String Challenge, int tipo, int clase) {
		String filename = "";
		SAXBuilder builder = new SAXBuilder();
		Document reg = null;
		try {

			if (clase == 2) {
				reg = builder.build(ConfigManager
						.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/data/" + "emitidosC2.xml");
			} else {
				reg = builder.build(ConfigManager
						.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/data/" + "emitidosC1.xml");
			}

			filename = DigestUtil.getMessageDigest(cert.getEncoded(),
					DigestType.MD5).replaceAll(":", "_")
					+ ".cer";

			XMLOutputter fmt = new XMLOutputter();
			Element regemitidos = reg.getRootElement();
			Element registro = new Element("CERTIFICADO");

//			String hex = "";
//			hex = Hex.decode(cert.getSerialNumber().toByteArray()).toString();
			registro.addContent(new Element("SERIAL").setText(cert.getSerialNumber().toString()));
			registro.addContent(new Element("CHALLENGE").setText(DigestUtil
					.getMessageDigest(Challenge.getBytes(), DigestType.MD5)));
			registro.addContent(new Element("EMAIL").setText(E));
			registro.addContent(new Element("FICHERO").setText(filename));
			registro.addContent(new Element("CN").setText(CN));
			registro.addContent(new Element("C").setText(C));
			registro.addContent(new Element("S").setText(ST));
			registro.addContent(new Element("L").setText(L));
			registro.addContent(new Element("TIPO").setText(String
					.valueOf(tipo)));
			regemitidos.addContent(registro);
			if (clase == 2) {
				fmt.output(reg, new FileOutputStream(ConfigManager
						.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/data/" + "emitidosC2.xml"));
			} else {
				fmt.output(reg, new FileOutputStream(ConfigManager
						.obtenerParametro("INSTALACION/DIRECTORIO")
						+ "/data/" + "emitidosC1.xml"));
			}
			return true;
		} catch (Exception ex) {
			return false;
		}
	}

	/**
	 * descargar
	 * 
	 * @param pin
	 *            String
	 * @param challenge
	 *            String
	 * @return X509Certificate
	 */
	public X509Certificate descargar(String pin, String challenge) {
		XMLOutputter out = new XMLOutputter();
		Document reg = null;
		SAXBuilder builder = new SAXBuilder();
		BASE64Decoder dec = new BASE64Decoder();
		File f = null;
		Element aux = null;
		byte[] cert = null;

		try {
			f = new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/data/" + "pendientes.xml");
			if (f.exists()) {
				reg = builder.build(f);
				List emitidos = reg.getRootElement().getChildren();
				Object[] tabla = emitidos.toArray();
				for (int i = 0; i < tabla.length; i++) {
					aux = (Element) tabla[i];
					if ((aux.getChild("PIN").getText().compareToIgnoreCase(pin) == 0)
							&& (aux.getChild("CHALLENGE").getText()
									.compareToIgnoreCase(
											DigestUtil.getMessageDigest(
													challenge.getBytes(),
													DigestType.MD5)) == 0)) {
						cert = dec.decodeBuffer(aux.getChild("CERT").getText());
						reg.getRootElement().removeChild(aux);
						out.output(reg, new FileOutputStream(f));
						return (X509Certificate) CertificateFactory
								.getInstance("X.509").generateCertificate(
										new ByteArrayInputStream(cert));
					}
				}

			} else {
				lastError = "Error al descargar el certificado, el fichero de registros pendientes no existe. \nPongase en contacto con el administrador del sistema.";
				return null;
			}
		} catch (Exception ex) {
			lastError = "Error, se produjo una excepcion y no se pudo completar la operacion. \nMensaje de la Excepcion: "
					+ ex.getMessage();
			return null;
		}
		return null;
	}

	/**
	 * renovarCA
	 */
	public boolean renovarCA(char[] storePassword, char[] keyPassword, int validez) {
		X509Certificate[] cacerts = null;
		String aux = "";
		FileOutputStream fos1 = null;
		FileOutputStream fos2 = null;

		try {
			cacerts = ca.renovarCA(storePassword, keyPassword, validez);
			aux = ConfigManager.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/html/Repositorio/";

			fos1 = new FileOutputStream(aux + "cacertclase1.crt");
			fos1.write(cacerts[0].getEncoded());
			fos1.close();
			
			fos2 = new FileOutputStream(aux + "cacertclase2.crt");
			fos2.write(cacerts[1].getEncoded());
			fos2.close();
			
			return true;

		} catch (Exception ex) {
			lastError = "Error, se produjo una excepcion y no se pudo completar la operacion. \nMensaje de la Excepcion: "
				+ ex.getMessage();
			return false;
		}
	}
	
	public boolean renovarCAWebSSL(char[] storePassword, char[] keyPassword){
		
			try {
				return ca.renovarCAWebSSL(storePassword, keyPassword);
			} catch (CAManagerException e) {
				lastError = "Error, no se pudo renovar el certificado de la web con SSL. \nMensaje de la excepcion: "
					+ e.getMessage();
				return false;
			}
	
	}
}
