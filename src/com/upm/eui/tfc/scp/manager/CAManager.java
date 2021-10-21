package com.upm.eui.tfc.scp.manager;

/**
 * Clase encargada implementar la Autoridad Certificadora. Es la encargada de gestionar las claves de la autoridad. Emite todos
 * los certificados asi como la CRL. Es el encargado de la generacion de los certificados asi como de la firma de los mismos.
 * Atiende solo las peticiones de la Autoridad de Registro. Es la encargada tambien de renovar, revocar, suspender, activar y
 * validar un certificado.
 * 
 * @version 1.0
 */

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.misc.NetscapeRevocationURL;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.X509V2CRLGenerator;
import org.bouncycastle.jce.X509V3CertificateGenerator;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;

import com.upm.eui.tfc.scp.excep.CAManagerException;
import com.upm.eui.tfc.scp.utiles.CryptoException;
import com.upm.eui.tfc.scp.utiles.KeyPairType;
import com.upm.eui.tfc.scp.utiles.KeyPairUtil;
import com.upm.eui.tfc.scp.utiles.KeyStoreType;
import com.upm.eui.tfc.scp.utiles.KeyStoreUtil;
import com.upm.eui.tfc.scp.utiles.SignatureType;
import com.upm.eui.tfc.scp.utiles.X509CertUtil;

public class CAManager {

	private KeyStore ks = null;
	private KeyStore ks_ssl = null;
	private X509Certificate[] cert = new X509Certificate[1];
	private KeyPair kp1 = null;
	private KeyPair kp2 = null;
	private SignatureType st = null;

	public Object[] crearCA(char[] storePassword, char[] keyPassword,
			String sCommonName, String sOrganisationUnit1,
			String sOrganisationUnit2, String sOrganisationUnit3,
			String sOrganisation, String sCountryCode, String Locality,
			String State, String Email, int iValidity, String keytype,
			int keylength, String sigtype) throws CAManagerException {
		Object[] retorno = new Object[3];
		KeyPair kpssl = null;
		String sitioweb = "";
		X509Certificate cacert1 = null;
		X509Certificate cacert2 = null;

		try {
			sitioweb = ConfigManager.obtenerParametro("CA/DOMINIO");
			ks = KeyStoreUtil.createKeyStore(KeyStoreType.JKS);
			ks.load(null, storePassword);
			ks_ssl = KeyStoreUtil.createKeyStore(KeyStoreType.JKS);
			ks_ssl.load(null, storePassword);
			if (keytype.compareToIgnoreCase("RSA") == 0) {
				kp1 = KeyPairUtil.generateKeyPair(KeyPairType.RSA, keylength);
				kp2 = KeyPairUtil.generateKeyPair(KeyPairType.RSA, keylength);
			} else {
				kp1 = KeyPairUtil.generateKeyPair(KeyPairType.DSA, keylength);
				kp2 = KeyPairUtil.generateKeyPair(KeyPairType.DSA, keylength);
			}
			if (sigtype.compareToIgnoreCase("SHA1withDSA") == 0) {
				st = SignatureType.DSA_SHA1;
			} else if (sigtype.compareToIgnoreCase("SHA1withRSA") == 0) {
				st = SignatureType.RSA_SHA1;
			} else if (sigtype.compareToIgnoreCase("MD2withRSA") == 0) {
				st = SignatureType.RSA_MD2;
			} else {
				st = SignatureType.RSA_MD5;
			}
			cert[0] = X509CertUtil.generateCACert(sCommonName,
					sOrganisationUnit1, sOrganisationUnit2, sOrganisationUnit3,
					sOrganisation, Locality, State, sCountryCode, Email,
					iValidity, kp2.getPublic(), kp2.getPrivate(), st, true);
			cacert2 = cert[0];
			ks.setCertificateEntry("ca2", cert[0]);
			ks.setKeyEntry("ca2", kp2.getPrivate(), keyPassword, cert);

			cert[0] = X509CertUtil.generateCACert(sCommonName,
					sOrganisationUnit1, sOrganisationUnit2, sOrganisationUnit3,
					sOrganisation, Locality, State, sCountryCode, Email,
					iValidity, kp1.getPublic(), kp1.getPrivate(), st, false);
			cacert1 = cert[0];
			ks.setCertificateEntry("ca1", cert[0]);
			ks.setKeyEntry("ca1", kp1.getPrivate(), keyPassword, cert);

			KeyStoreUtil.saveKeyStore(ks, new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/certs/ca.ks"), storePassword);

			// Certificado para SSL del servidor seguro
			kpssl = KeyPairUtil.generateKeyPair(KeyPairType.RSA, 2048);
			cert[0] = X509CertUtil.generateCert(sitioweb, "Sitio Web Seguro",
					sOrganisation, Locality, State, sCountryCode, Email, 3650,
					kpssl.getPublic(), kp2.getPrivate(), SignatureType.RSA_MD5,
					cacert2.getIssuerDN().toString());

			ks_ssl.setCertificateEntry("ca2",cacert2);
			ks_ssl.setCertificateEntry(sitioweb, cert[0]);
			ks_ssl.setKeyEntry(sitioweb, kpssl.getPrivate(), keyPassword, cert);

			KeyStoreUtil.saveKeyStore(ks_ssl, new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/certs/ssl.ks"), storePassword);

			retorno[0] = cacert2;
			retorno[1] = generarCRL(kp2.getPrivate(), invertirCadena(cacert2
					.getIssuerDN().toString()), cacert2.getSigAlgName());
			retorno[2] = cacert1;
			return retorno;
		} catch (CAManagerException ex) {
			throw new CAManagerException(
					"Error al generar la CRL incial. \nLa CA se inicializo correctamente pero no se pudo generar la CRL.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (KeyStoreException ex) {
			throw new CAManagerException(
					"Error al acceder al Keystore. \nNo se pudo inicializar la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (IOException ex) {
			throw new CAManagerException(
					"Error de entrada/salida. No se pudo acceder al Keystore. \nNo se inicializo la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (CertificateException ex) {
			throw new CAManagerException(
					"Error al generar el certificaco. \nNo se pudo inicializar la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (NoSuchAlgorithmException ex) {
			throw new CAManagerException(
					"Error de algoritmo. No existe el algoritmo en le proveedor facilitado. \nNo se inicializo la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (CryptoException ex) {
			throw new CAManagerException(
					"Error criptografico. \nNo se inicializo la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (Exception ex) {
			throw new CAManagerException(
					"Error desconocido. \nNo se inicializo la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		}
	}

	private X509CRL generarCRL(PrivateKey pk, String issuer, String algoritmo)
			throws CAManagerException {
		try {
			X509V2CRLGenerator genCrl = new X509V2CRLGenerator();

			genCrl.setIssuerDN(new X509Principal(invertirCadena(issuer)));
			genCrl.setSignatureAlgorithm(algoritmo);
			genCrl.setThisUpdate(new Date());
			genCrl.setNextUpdate(new Date(System.currentTimeMillis()
					+ (24 * 60 * 60 * 1000)));
			return genCrl.generateX509CRL(pk);
		} catch (Exception e) {
			throw new CAManagerException("");
		}

	}

	public X509Certificate emitirCP(String sCommonName, String sEmailAddress,
			String sCountryCode, String sState, String sLocality, PublicKey pk,
			int iValidity, char[] storePassword, char[] keyPassword, int clase)
			throws CAManagerException {
		PrivateKey privatekey = null;
		String subject = "";
		X509Certificate cacert = null;
		

		try {
			ks = KeyStoreUtil.loadKeyStore(new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/certs/ca.ks"), storePassword, KeyStoreType.JKS);
			if (clase == 2) {
				cacert = (X509Certificate) ks.getCertificate("ca2");
				privatekey = (PrivateKey) ks.getKey("ca2", keyPassword);
			} else {
				cacert = (X509Certificate) ks.getCertificate("ca1");
				privatekey = (PrivateKey) ks.getKey("ca1", keyPassword);

			}

			if (sEmailAddress.compareTo("") != 0) {
				subject = subject + "E=" + sEmailAddress;
			}
			if (sCountryCode.compareTo("") != 0) {
				subject = subject + ", C=" + sCountryCode;
			}

			if (sState.compareTo("") != 0) {
				subject = subject + ", ST=" + sState;
			}

			if (sLocality.compareTo("") != 0) {
				subject = subject + ", L=" + sLocality;
			}

			subject = subject + ","
					+ completarDn(cacert.getIssuerDN().toString());
			subject = subject + ", OU=Certificado Clase " + clase;

			if (sCommonName.compareTo("") != 0) {
				subject = subject + ", CN=" + sCommonName;
			}

			// Get an X509 Version 1 Certificate generator
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

			// Cargamos las extensiones

			certGen.addExtension(X509Extensions.BasicConstraints, false,
					new BasicConstraints(false));

			certGen.addExtension(MiscObjectIdentifiers.netscapeCertType, false,
					new NetscapeCertType(NetscapeCertType.smime
							| NetscapeCertType.sslClient));
			certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
					createSubjectKeyId(pk));
			if (clase == 2) {
				NetscapeRevocationURL nca = new NetscapeRevocationURL(
						new DERIA5String(ConfigManager
								.obtenerParametro("CA/URLACTIVA")
								+ "/Repositorio/ultimaCRL.crl"));
				certGen
						.addExtension(
								MiscObjectIdentifiers.netscapeRevocationURL,
								false, nca);

				ArrayList distpoints = new ArrayList();
				GeneralName gn = new GeneralName(new DERIA5String(ConfigManager
						.obtenerParametro("CA/URLACTIVA")
						+ "/Repositorio/ultimaCRL.crl"), 6);
				ASN1EncodableVector vec = new ASN1EncodableVector();
				vec.add(gn);
				GeneralNames gns = new GeneralNames(new DERSequence(vec));
				DistributionPointName dpn = new DistributionPointName(0, gns);
				distpoints.add(new DistributionPoint(dpn, null, null));

				CRLDistPoint ext = new CRLDistPoint(
						(DistributionPoint[]) distpoints
								.toArray(new DistributionPoint[0]));
				certGen.addExtension(X509Extensions.CRLDistributionPoints
						.getId(), false, ext);

			}

			certGen.addExtension(X509Extensions.KeyUsage.getId(), false,
					new X509KeyUsage(X509KeyUsage.digitalSignature
							| X509KeyUsage.keyEncipherment));

			DEREncodableVector dervec = new DEREncodableVector();
			GeneralName altgn = new GeneralName(
					new DERIA5String(sEmailAddress), 1);
			dervec.add(altgn);
			GeneralNames san = new GeneralNames(new DERSequence(dervec));
			certGen.addExtension(X509Extensions.SubjectAlternativeName.getId(),
					false, san);

			// Load the generator with generation parameters
			 X509Principal principal = new
			 X509Principal(invertirCadena(cacert.
			 getSubjectDN().
			 toString()));

			
			// Set the issuer distinguished name
			certGen.setIssuerDN(principal);

			// Valid before and after dates now to iValidity days in the future
			certGen.setNotBefore(new Date(System.currentTimeMillis()));
			certGen.setNotAfter(new Date(System.currentTimeMillis()
					+ ((long) iValidity * 24 * 60 * 60 * 1000)));

			// Set the subject distinguished name (same as issuer for our
			// purposes)
			certGen.setSubjectDN(new X509Principal(subject));

			// Set the public key
			certGen.setPublicKey(pk);

			// Set the algorithm
			certGen.setSignatureAlgorithm(cacert.getSigAlgName());

			// Set the serial number
			certGen.setSerialNumber(new BigInteger(Long.toString(System
					.currentTimeMillis() / 1000)));

			// Generate an X.509 certificate, based on the current issuer and
			// subject

			return certGen.generateX509Certificate(privatekey);
		} catch (KeyStoreException ex) {
			throw new CAManagerException(
					"Error al acceder al Keystore.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (IOException ex) {
			throw new CAManagerException(
					"Error de entrada/salida. No se pudo acceder al Keystore.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (NoSuchAlgorithmException ex) {
			throw new CAManagerException(
					"Error de algoritmo. No existe el algoritmo en le proveedor facilitado.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (CryptoException ex) {
			throw new CAManagerException(
					"Error criptografico.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (SignatureException ex) {
			throw new CAManagerException(
					"Error al firmar el certificado.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (InvalidKeyException ex) {
			throw new CAManagerException(
					"Error de claves. Las clave no es correcta.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (UnrecoverableKeyException ex) {
			throw new CAManagerException(
					"Error al recuperar la clave de la CA para firmar.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (org.jdom.JDOMException ex) {
			throw new CAManagerException(
					"Error al acceder el fichero XML de configuracion.\nMensaje de la excepcion: "
							+ ex.getMessage());
		}
	}

	/**
	 * completarDn
	 * 
	 * @param string
	 *            String
	 * @return String
	 */
	public String completarDn(String casubject) {
		String[] aux1 = casubject.split(",");
		String[] aux3 = null;
		String aux2 = "";

		for (int i = 0; i <= aux1.length - 1; i++) {
			aux3 = aux1[i].split("=");
			if ((aux3[0].trim().compareToIgnoreCase("OU") == 0)
					|| (aux3[0].trim().compareToIgnoreCase("O") == 0)) {
				aux2 += aux1[i] + ",";
			}
		}
		return invertirCadena(aux2);
	}

	public X509CRL revocar(X509Certificate cert, char[] storePassword,
			char[] keyPassword, int motivo) throws CAManagerException {
		PrivateKey privatekey = null;
		X509Certificate cacert = null;
		X509CRL crlantigua = null;
		CertificateFactory cf = null;
		Set revocados = null;
		X509CRL crlnueva = null;

		try {
			ks = KeyStoreUtil.loadKeyStore(new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/certs/ca.ks"), storePassword, KeyStoreType.JKS);

			cacert = (X509Certificate) ks.getCertificate("ca2");

			privatekey = (PrivateKey) ks.getKey("ca2", keyPassword);

			// Load the generator with generation parameters
//			X509Principal principal = new X509Principal(invertirCadena(cacert
//					.getSubjectDN().toString()));
			
			X509Principal principal = new X509Principal(cacert
					.getSubjectDN().toString());
			
			File crlfile = new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/html/Repositorio/ultimaCRL.crl");
			cf = CertificateFactory.getInstance("X509");
			if (crlfile.exists()) {
				FileInputStream fis = new FileInputStream(crlfile);
				crlantigua = (X509CRL) cf.generateCRL(fis);
				fis.close();
			} else {
				crlantigua = null;
			}

			X509V2CRLGenerator genCrl = new X509V2CRLGenerator();

			genCrl.setIssuerDN(principal);
			genCrl.setSignatureAlgorithm(cacert.getSigAlgName());
			genCrl.setThisUpdate(new Date());
			genCrl.setNextUpdate(new Date(System.currentTimeMillis()
					+ (24 * 60 * 60 * 1000)));

			if (crlantigua != null) {
				revocados = crlantigua.getRevokedCertificates();
				if (revocados != null) {
					Object lista[] = revocados.toArray();
					for (int i = 0; i < lista.length; i++) {
						X509CRLEntry aux = (X509CRLEntry) lista[i];
						genCrl.addCRLEntry(aux.getSerialNumber(), aux
								.getRevocationDate(), obtenerMotivo(aux
								.getSerialNumber().toString()));
					}
				}
			}

			genCrl.addCRLEntry(cert.getSerialNumber(), new Date(), motivo);
			crlnueva = genCrl.generateX509CRL(privatekey);

			FileOutputStream fos = new FileOutputStream(crlfile, false);
			fos.write(crlnueva.getEncoded());
			fos.close();

			return crlnueva;
		} catch (KeyStoreException ex) {
			throw new CAManagerException(
					"Error al acceder al Keystore.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (IOException ex) {
			throw new CAManagerException(
					"Error de entrada/salida. No se pudo acceder al Keystore.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (NoSuchAlgorithmException ex) {
			throw new CAManagerException(
					"Error de algoritmo. No existe el algoritmo en le proveedor facilitado.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (CryptoException ex) {
			throw new CAManagerException(
					"Error criptografico.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (SignatureException ex) {
			throw new CAManagerException(
					"Error al firmar el certificado.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (InvalidKeyException ex) {
			throw new CAManagerException(
					"Error de claves. Las clave no es correcta.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (UnrecoverableKeyException ex) {
			throw new CAManagerException(
					"Error al recuperar la clave de la CA para firmar.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (org.jdom.JDOMException ex) {
			throw new CAManagerException(
					"Error al acceder el fichero XML de configuracion.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (CRLException ex) {
			throw new CAManagerException(
					"Error al obtener la instancia de la CRL.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (CertificateException ex) {
			throw new CAManagerException(
					"Error al obtener la instancia del certificado.\nMensaje de la excepcion: "
							+ ex.getMessage());
		}
	}

	/**
	 * obtenerMotivo
	 * 
	 * @param string
	 *            String
	 * @return int
	 */
	private int obtenerMotivo(String serial) {
		Element aux = null;
		Object[] tabla = null;

		try {
			SAXBuilder builder = new SAXBuilder();
			Document reg = builder.build(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/data/revocados.xml");
			List revocados = reg.getRootElement().getChildren();
			tabla = revocados.toArray();
			for (int i = 0; i < tabla.length; i++) {
				aux = (Element) tabla[i];
				if (aux.getChild("SERIAL").getText()
						.compareToIgnoreCase(serial) == 0) {
					return Integer.parseInt(aux.getChild("MOTIVO").getText());
				}
			}
			return 1;
		} catch (Exception e) {
			return 1;
		}
	}

	public String validar(char[] storePassword, X509Certificate cert) {
		X509Certificate cacert = null;
		X509CRL crl = null;

		try {
			ks = KeyStoreUtil.loadKeyStore(new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/certs/ca.ks"), storePassword, KeyStoreType.JKS);
			cacert = (X509Certificate) ks.getCertificate("ca2");

			crl = (X509CRL) CertificateFactory.getInstance("X509").generateCRL(
					new FileInputStream(ConfigManager
							.obtenerParametro("INSTALACION/DIRECTORIO")
							+ "/html/Repositorio/ultimaCRL.crl"));

			cert.checkValidity();

			if (crl.isRevoked(cert)) {
				if (estaSuspendido(cert.getSerialNumber().toString())) {
					return "SUSPENDIDO";
				} else {
					return "REVOCADO";
				}
			} else {

				if (X509CertUtil.verifyCertificate(cert, cacert)) {
					return "VALIDO";
				} else {
					return "DESCONOCIDO";
				}
			}
		} catch (CertificateExpiredException ex) {
			return "EXPIRADO";
		} catch (CertificateNotYetValidException ex) {
			return "AUN NO VALIDO";
		} catch (Exception ex) {
			return "DESCONOCIDO";
		}

	}

	/**
	 * estaSuspendido
	 * 
	 * @param string
	 *            String
	 * @return boolean
	 */
	private boolean estaSuspendido(String serial) {
		Element aux = null;
		Object[] tabla = null;

		try {
			SAXBuilder builder = new SAXBuilder();
			Document reg = builder.build(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/data/suspendidos.xml");
			List revocados = reg.getRootElement().getChildren();
			tabla = revocados.toArray();
			for (int i = 0; i < tabla.length; i++) {
				aux = (Element) tabla[i];
				if (aux.getChild("SERIAL").getText()
						.compareToIgnoreCase(serial) == 0) {
					return true;
				}
			}
			return false;
		} catch (Exception e) {
			return false;
		}

	}

	public String invertirCadena(String cadena) {
		String[] aux1 = cadena.split(",");
		int i = 0;
		int j = aux1.length - 1;
		String[] aux2 = new String[j + 1];
		String aux3 = "";

		while (j >= 0) {
			aux2[i] = aux1[j];
			i++;
			j--;
		}

		for (int k = 0; k < aux2.length - 1; k++) {
			aux3 += aux2[k] + ",";

		}
		return aux3 += aux2[aux2.length - 1];

	}

	public void suspender(X509Certificate cert, char[] storePassword,
			char[] keyPassword) throws CAManagerException {
		revocar(cert, storePassword, keyPassword, 6);
	}

	public void reactivar(X509Certificate cert, char[] storePassword,
			char[] keyPassword) throws CAManagerException {
		PrivateKey privatekey = null;
		X509Certificate cacert = null;
		X509CRL crlantigua = null;
		CertificateFactory cf = null;
		Set revocados = null;
		X509CRL crlnueva = null;

		try {
			ks = KeyStoreUtil.loadKeyStore(new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/certs/ca.ks"), storePassword, KeyStoreType.JKS);

			cacert = (X509Certificate) ks.getCertificate("ca2");

			privatekey = (PrivateKey) ks.getKey("ca2", keyPassword);

			// Load the generator with generation parameters
			X509Principal principal = new X509Principal(invertirCadena(cacert
					.getSubjectDN().toString()));
			File crlfile = new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/html/Repositorio/ultimaCRL.crl");
			cf = CertificateFactory.getInstance("X509");
			if (crlfile.exists()) {
				FileInputStream fis = new FileInputStream(crlfile);
				crlantigua = (X509CRL) cf.generateCRL(fis);
				fis.close();
			} else {
				throw new CAManagerException("Error al acceder a la CRL");
			}

			X509V2CRLGenerator genCrl = new X509V2CRLGenerator();

			genCrl.setIssuerDN(principal);
			genCrl.setSignatureAlgorithm(cacert.getSigAlgName());
			genCrl.setThisUpdate(new Date());
			genCrl.setNextUpdate(new Date(System.currentTimeMillis()
					+ (24 * 60 * 60 * 1000)));

			if (crlantigua != null) {
				revocados = crlantigua.getRevokedCertificates();
				Object lista[] = revocados.toArray();
				for (int i = 0; i < lista.length; i++) {
					X509CRLEntry aux = (X509CRLEntry) lista[i];
					if (aux.getSerialNumber().compareTo(cert.getSerialNumber()) != 0) {
						genCrl.addCRLEntry(aux.getSerialNumber(), aux
								.getRevocationDate(), obtenerMotivo(aux
								.getSerialNumber().toString()));
					}
				}
			}

			crlnueva = genCrl.generateX509CRL(privatekey);

			FileOutputStream fos = new FileOutputStream(crlfile, false);
			fos.write(crlnueva.getEncoded());
			fos.close();
		} catch (KeyStoreException ex) {
			throw new CAManagerException(
					"Error al acceder al Keystore.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (IOException ex) {
			throw new CAManagerException(
					"Error de entrada/salida. No se pudo acceder al Keystore.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (NoSuchAlgorithmException ex) {
			throw new CAManagerException(
					"Error de algoritmo. No existe el algoritmo en le proveedor facilitado.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (CryptoException ex) {
			throw new CAManagerException(
					"Error criptografico.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (SignatureException ex) {
			throw new CAManagerException(
					"Error al firmar el certificado.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (InvalidKeyException ex) {
			throw new CAManagerException(
					"Error de claves. Las clave no es correcta.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (UnrecoverableKeyException ex) {
			throw new CAManagerException(
					"Error al recuperar la clave de la CA para firmar.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (org.jdom.JDOMException ex) {
			throw new CAManagerException(
					"Error al acceder el fichero XML de configuracion.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (CRLException ex) {
			throw new CAManagerException(
					"Error al obtener la instancia de la CRL.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (CertificateException ex) {
			throw new CAManagerException(
					"Error al obtener la instancia del certificado.\nMensaje de la excepcion: "
							+ ex.getMessage());
		}
	}

	/**
	 * obtenerDN
	 * 
	 * @return String
	 */
	public String obtenerDN(char[] storePassword) {
		X509Certificate cacert = null;
		try {
			ks = KeyStoreUtil.loadKeyStore(new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/certs/ca.ks"), storePassword, KeyStoreType.JKS);

			cacert = (X509Certificate) ks.getCertificate("ca2");
			return cacert.getSubjectDN().toString();
		} catch (Exception e) {
			return null;
		}
	}

	public static SubjectKeyIdentifier createSubjectKeyId(PublicKey pubKey) {
		try {
			ByteArrayInputStream bIn = new ByteArrayInputStream(pubKey
					.getEncoded());
			SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
					(ASN1Sequence) new DERInputStream(bIn).readObject());

			return new SubjectKeyIdentifier(info);
		} catch (Exception e) {
			throw new RuntimeException("Error al crear la clave.");
		}
	}

	public X509Certificate emitirSSL(String csr, PublicKey pk, int iValidity,
			char[] storePassword, char[] keyPassword, int clase)
			throws CAManagerException {
		PrivateKey privatekey = null;
		X509Certificate cacert = null;

		try {
			ks = KeyStoreUtil.loadKeyStore(new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/certs/ca.ks"), storePassword, KeyStoreType.JKS);
			if (clase == 2) {
				cacert = (X509Certificate) ks.getCertificate("ca2");
				privatekey = (PrivateKey) ks.getKey("ca2", keyPassword);
			} else {
				cacert = (X509Certificate) ks.getCertificate("ca1");
				privatekey = (PrivateKey) ks.getKey("ca1", keyPassword);
			}

			// Get an X509 Version 1 Certificate generator
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

			// Cargamos las extensiones

			certGen.addExtension(X509Extensions.BasicConstraints, false,
					new BasicConstraints(false));
			certGen.addExtension(MiscObjectIdentifiers.netscapeCertType, false,
					new NetscapeCertType(NetscapeCertType.sslServer));
			certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
					createSubjectKeyId(pk));
			if (clase == 2) {
				NetscapeRevocationURL nca = new NetscapeRevocationURL(
						new DERIA5String(ConfigManager
								.obtenerParametro("CA/URLACTIVA")
								+ "/Repositorio/ultimaCRL.crl"));
				certGen
						.addExtension(
								MiscObjectIdentifiers.netscapeRevocationURL,
								false, nca);

				ArrayList distpoints = new ArrayList();
				GeneralName gn = new GeneralName(new DERIA5String(ConfigManager
						.obtenerParametro("CA/URLACTIVA")
						+ "/Repositorio/ultimaCRL.crl"), 6);
				ASN1EncodableVector vec = new ASN1EncodableVector();
				vec.add(gn);
				GeneralNames gns = new GeneralNames(new DERSequence(vec));
				DistributionPointName dpn = new DistributionPointName(0, gns);
				distpoints.add(new DistributionPoint(dpn, null, null));

				CRLDistPoint ext = new CRLDistPoint(
						(DistributionPoint[]) distpoints
								.toArray(new DistributionPoint[0]));
				certGen.addExtension(X509Extensions.CRLDistributionPoints
						.getId(), false, ext);
			}

			// Load the generator with generation parameters
			X509Principal principal = new X509Principal(invertirCadena(cacert
					.getSubjectDN().toString()));
			
			// Set the issuer distinguished name
			certGen.setIssuerDN(principal);

			// Valid before and after dates now to iValidity days in the future
			certGen.setNotBefore(new Date(System.currentTimeMillis()));
			certGen.setNotAfter(new Date(System.currentTimeMillis()
					+ ((long) iValidity * 24 * 60 * 60 * 1000)));

			// Set the subject distinguished name (same as issuer for our
			// purposes)
			// certGen.setSubjectDN(new X509Principal(csr.replaceFirst(",",
			// ", OU=Certificado Clase " + clase + ",")));
			certGen.setSubjectDN(new X509Principal(csr));
			// Set the public key
			certGen.setPublicKey(pk);

			// Set the algorithm
			certGen.setSignatureAlgorithm(cacert.getSigAlgName());

			// Set the serial number
			certGen.setSerialNumber(new BigInteger(Long.toString(System
					.currentTimeMillis() / 1000)));

			// Generate an X.509 certificate, based on the current issuer and
			// subject

			return certGen.generateX509Certificate(privatekey);
		} catch (KeyStoreException ex) {
			throw new CAManagerException(
					"Error al acceder al Keystore.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (IOException ex) {
			throw new CAManagerException(
					"Error de entrada/salida. No se pudo acceder al Keystore.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (NoSuchAlgorithmException ex) {
			throw new CAManagerException(
					"Error de algoritmo. No existe el algoritmo en le proveedor facilitado.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (CryptoException ex) {
			throw new CAManagerException(
					"Error criptografico.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (SignatureException ex) {
			throw new CAManagerException(
					"Error al firmar el certificado.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (InvalidKeyException ex) {
			throw new CAManagerException(
					"Error de claves. Las clave no es correcta.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (UnrecoverableKeyException ex) {
			throw new CAManagerException(
					"Error al recuperar la clave de la CA para firmar.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (org.jdom.JDOMException ex) {
			throw new CAManagerException(
					"Error al acceder el fichero XML de configuracion.\nMensaje de la excepcion: "
							+ ex.getMessage());
		}
	}

	public X509Certificate[] renovarCA(char[] storePassword, char[] keyPassword,
			int validez) throws CAManagerException {

		PrivateKey pk = null;
		X509Certificate[] return_certs = new X509Certificate[2];
		X509Certificate[] certs = new X509Certificate[1];
		
		try {
			File f1 = new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/certs/ca.ks");
			
			ks = KeyStoreUtil.createKeyStore(KeyStoreType.JKS);
			ks = KeyStoreUtil.loadKeyStore(f1, storePassword, KeyStoreType.JKS);

			certs[0] = (X509Certificate) ks.getCertificate("ca1");
			pk = (PrivateKey) ks.getKey("ca1", keyPassword);

			return_certs[0] = X509CertUtil.renovarCACert(certs[0], pk, validez);
			certs[0] = return_certs[0];

			ks.deleteEntry("ca1");
			ks.setCertificateEntry("ca1", certs[0]);
			ks.setKeyEntry("ca1", pk, keyPassword, certs);

			certs[0] = (X509Certificate) ks.getCertificate("ca2");
			pk = (PrivateKey) ks.getKey("ca2", keyPassword);

			return_certs[1] = X509CertUtil.renovarCACert(certs[0], pk, validez);
			certs[0] = return_certs[1];
			
			ks.deleteEntry("ca2");
			ks.setCertificateEntry("ca2", certs[0]);
			ks.setKeyEntry("ca2", pk, keyPassword, certs);
			
			KeyStoreUtil.saveKeyStore(ks, f1, storePassword);
			return return_certs;
		} catch (CAManagerException ex) {
			throw new CAManagerException(
					"Error al generar la CRL incial. \nLa CA se inicializo correctamente pero no se pudo generar la CRL.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (KeyStoreException ex) {
			throw new CAManagerException(
					"Error al acceder al Keystore. \nNo se pudo inicializar la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (IOException ex) {
			throw new CAManagerException(
					"Error de entrada/salida. No se pudo acceder al Keystore. \nNo se inicializo la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (NoSuchAlgorithmException ex) {
			throw new CAManagerException(
					"Error de algoritmo. No existe el algoritmo en le proveedor facilitado. \nNo se inicializo la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (CryptoException ex) {
			throw new CAManagerException(
					"Error criptografico. \nNo se inicializo la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (Exception ex) {
			throw new CAManagerException(
					"Error desconocido. \nNo se inicializo la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		}
	}
	
	public boolean renovarCAWebSSL(char[] storePassword, char[] keyPassword) throws CAManagerException {

		PrivateKey pk = null;
		X509Certificate[] certs = new X509Certificate[1];
		String sitioweb = null;
		
		try {
			sitioweb = ConfigManager.obtenerParametro("CA/DOMINIO");
			File f1 = new File(ConfigManager
					.obtenerParametro("INSTALACION/DIRECTORIO")
					+ "/certs/ssl.ks");
			
			ks = KeyStoreUtil.createKeyStore(KeyStoreType.JKS);
			ks = KeyStoreUtil.loadKeyStore(f1, storePassword, KeyStoreType.JKS);

			certs[0] = (X509Certificate) ks.getCertificate(sitioweb);
			pk = (PrivateKey) ks.getKey(sitioweb, keyPassword);

			certs[0] = this.emitirSSL(certs[0].getSubjectDN().toString(), certs[0].getPublicKey(), 365, storePassword, keyPassword, 2);
			ks.deleteEntry(sitioweb);
			ks.setCertificateEntry(sitioweb, certs[0]);
			ks.setKeyEntry(sitioweb, pk, keyPassword, certs);
			
			KeyStoreUtil.saveKeyStore(ks, f1, storePassword);
			return true;
		} catch (CAManagerException ex) {
			throw new CAManagerException(
					"Error al generar la CRL incial. \nLa CA se inicializo correctamente pero no se pudo generar la CRL.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (KeyStoreException ex) {
			throw new CAManagerException(
					"Error al acceder al Keystore. \nNo se pudo inicializar la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (IOException ex) {
			throw new CAManagerException(
					"Error de entrada/salida. No se pudo acceder al Keystore. \nNo se inicializo la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (NoSuchAlgorithmException ex) {
			throw new CAManagerException(
					"Error de algoritmo. No existe el algoritmo en le proveedor facilitado. \nNo se inicializo la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (CryptoException ex) {
			throw new CAManagerException(
					"Error criptografico. \nNo se inicializo la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		} catch (Exception ex) {
			throw new CAManagerException(
					"Error desconocido. \nNo se inicializo la CA.\nMensaje de la excepcion: "
							+ ex.getMessage());
		}
	}
}
