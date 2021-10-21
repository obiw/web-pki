package com.upm.eui.tfc.scp.utiles;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInputStream;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.misc.NetscapeRevocationURL;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.X509V3CertificateGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.jdom.JDOMException;

import com.upm.eui.tfc.scp.excep.CAManagerException;
import com.upm.eui.tfc.scp.manager.ConfigManager;

/**
 * Clase que encapsula distintos metodos y procedimientos utiles para el manejo
 * de extensiones de certificados digitales (X509).
 * 
 * @version 1.0
 */

public final class X509CertUtil extends Object {

	private static final String X509_CERT_TYPE = "X.509";

	private static final String PKCS7_ENCODING = "PKCS7";

	private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";

	private static final String END_CERT = "-----END CERTIFICATE-----";

	private static final int CERT_LINE_LENGTH = 64;

	private static final String BEGIN_CERT_REQ = "-----BEGIN CERTIFICATE REQUEST-----";

	private static final String END_CERT_REQ = "-----END CERTIFICATE REQUEST-----";

	private static final int CERT_REQ_LINE_LENGTH = 76;

	private X509CertUtil() {
	}

	public static X509Certificate[] loadCertificates(File fCertFile)
			throws CryptoException, FileNotFoundException, IOException {
		Vector vCerts = new Vector();

		FileInputStream fis = null;

		try {
			fis = new FileInputStream(fCertFile);

			CertificateFactory cf = CertificateFactory
					.getInstance(X509_CERT_TYPE);

			Collection coll = cf.generateCertificates(fis);
			Iterator iter = coll.iterator();

			while (iter.hasNext()) {
				X509Certificate cert = (X509Certificate) iter.next();
				if (cert != null) {
					vCerts.add(cert);
				}
			}
		} catch (CertificateException ex) {
			throw new CryptoException("NoLoadCertificate.exception.message", ex);
		} finally {
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException ex) { /* Ignorar */
				}
			}
			;
		}

		return (X509Certificate[]) vCerts.toArray(new X509Certificate[vCerts
				.size()]);
	}

	public static X509CRL loadCRL(File fCRLFile) throws CryptoException,
			FileNotFoundException, IOException {
		FileInputStream fis = null;

		try {
			fis = new FileInputStream(fCRLFile);
			CertificateFactory cf = CertificateFactory
					.getInstance(X509_CERT_TYPE);
			X509CRL crl = (X509CRL) cf.generateCRL(fis);
			return crl;
		} catch (CertificateException ex) {
			throw new CryptoException("NoLoadCrl.exception.message", ex);
		} catch (CRLException ex) {
			throw new CryptoException("NoLoadCrl.exception.message", ex);
		} finally {
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException ex) { /* Ignorar */
				}
			}
			;
		}
	}

	public static PKCS10CertificationRequest loadCSR(File fCSRFile)
			throws CryptoException, FileNotFoundException, IOException {
		InputStreamReader isr = null;
		StringWriter sw = null;
		LineNumberReader lnr = null;

		try {

			isr = new InputStreamReader(new FileInputStream(fCSRFile));
			sw = new StringWriter();

			int iRead;
			char buff[] = new char[1024];

			while ((iRead = isr.read(buff, 0, buff.length)) != -1) {
				sw.write(buff, 0, iRead);
			}

			StringBuffer strBuff = new StringBuffer();

			lnr = new LineNumberReader(new StringReader(sw.toString()));

			String sLine = null;
			while ((sLine = lnr.readLine()) != null) {
				if (sLine.length() > 0) {
					char c = sLine.charAt(0);

					if (((c > 'A') && (c <= 'Z')) || ((c > 'a') && (c <= 'z'))
							|| ((c > '0') && (c <= '9')) || (c == '+')
							|| (c == '/') || (c == '=')) {
						strBuff.append(sLine);
					}
				}
			}

			byte[] bDecodedReq = Base64.decode(strBuff.toString());

			PKCS10CertificationRequest csr = new PKCS10CertificationRequest(
					bDecodedReq);

			if (!csr.verify()) {
				throw new CryptoException("NoVerifyCsr.exception.message");
			}

			return csr;
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException("NoLoadCsr.exception.message", ex);
		} catch (NoSuchProviderException ex) {
			throw new CryptoException("NoLoadCsr.exception.message", ex);
		} catch (InvalidKeyException ex) {
			throw new CryptoException("NoLoadCsr.exception.message", ex);
		} catch (SignatureException ex) {
			throw new CryptoException("NoLoadCsr.exception.message", ex);
		}

		finally {
			if (isr != null) {
				try {
					isr.close();
				} catch (IOException ex) { /* Ignorar */
				}
			}
			;
			if (sw != null) {
				try {
					sw.close();
				} catch (IOException ex) { /* Ignorar */
				}
			}
			;
			if (lnr != null) {
				try {
					lnr.close();
				} catch (IOException ex) { /* Ignorar */
				}
			}
			;
		}
	}

	public static X509Certificate[] convertCertificates(Certificate[] certsIn)
			throws CryptoException {
		X509Certificate[] certsOut = new X509Certificate[certsIn.length];

		for (int iCnt = 0; iCnt < certsIn.length; iCnt++) {
			certsOut[iCnt] = convertCertificate(certsIn[iCnt]);
		}

		return certsOut;
	}

	public static X509Certificate convertCertificate(Certificate certIn)
			throws CryptoException {
		try {
			CertificateFactory cf = CertificateFactory
					.getInstance(X509_CERT_TYPE);
			ByteArrayInputStream bais = new ByteArrayInputStream(certIn
					.getEncoded());
			return (X509Certificate) cf.generateCertificate(bais);
		} catch (CertificateException ex) {
			throw new CryptoException("NoConvertCertificate.exception.message",
					ex);
		}
	}

	public static X509Certificate[] orderX509CertChain(X509Certificate certs[]) {
		int iOrdered = 0;
		X509Certificate[] tmpCerts = (X509Certificate[]) certs.clone();
		X509Certificate[] orderedCerts = new X509Certificate[certs.length];

		X509Certificate issuerCert = null;

		for (int iCnt = 0; iCnt < tmpCerts.length; iCnt++) {
			X509Certificate aCert = tmpCerts[iCnt];
			if (aCert.getIssuerDN().equals(aCert.getSubjectDN())) {
				issuerCert = aCert;
				orderedCerts[iOrdered] = issuerCert;
				iOrdered++;
			}
		}

		if (issuerCert == null) {
			return certs;
		}

		while (true) {
			boolean bFoundNext = false;
			for (int iCnt = 0; iCnt < tmpCerts.length; iCnt++) {
				X509Certificate aCert = tmpCerts[iCnt];

				if ((aCert.getIssuerDN().equals(issuerCert.getSubjectDN()))
						&& (aCert != issuerCert)) {

					issuerCert = aCert;
					orderedCerts[iOrdered] = issuerCert;
					iOrdered++;
					bFoundNext = true;
					break;
				}
			}
			if (!bFoundNext) {
				break;
			}
		}

		tmpCerts = new X509Certificate[iOrdered];
		System.arraycopy(orderedCerts, 0, tmpCerts, 0, iOrdered);

		orderedCerts = new X509Certificate[iOrdered];

		for (int iCnt = 0; iCnt < iOrdered; iCnt++) {
			orderedCerts[iCnt] = tmpCerts[tmpCerts.length - 1 - iCnt];
		}

		return orderedCerts;
	}

	public static byte[] getCertEncodedDer(X509Certificate cert)
			throws CryptoException {
		try {
			return cert.getEncoded();
		} catch (CertificateException ex) {
			throw new CryptoException("NoDerEncode.exception.message", ex);
		}
	}

	public static String getCertEncodedPem(X509Certificate cert)
			throws CryptoException {
		try {

			String sTmp = new String(Base64.encode(cert.getEncoded()));

			String sEncoded = BEGIN_CERT + "\n";

			for (int iCnt = 0; iCnt < sTmp.length(); iCnt += CERT_LINE_LENGTH) {
				int iLineLength;

				if ((iCnt + CERT_LINE_LENGTH) > sTmp.length()) {
					iLineLength = (sTmp.length() - iCnt);
				} else {
					iLineLength = CERT_LINE_LENGTH;
				}

				sEncoded += sTmp.substring(iCnt, (iCnt + iLineLength)) + "\n";
			}

			sEncoded += END_CERT + "\n";

			return sEncoded;
		} catch (CertificateException ex) {
			throw new CryptoException("NoPemEncode.exception.message", ex);
		}
	}

	public static byte[] getCertEncodedPkcs7(X509Certificate cert)
			throws CryptoException {
		return getCertsEncodedPkcs7(new X509Certificate[] { cert });
	}

	public static byte[] getCertsEncodedPkcs7(X509Certificate[] certs)
			throws CryptoException {
		try {
			ArrayList alCerts = new ArrayList();

			for (int iCnt = 0; iCnt < certs.length; iCnt++) {
				alCerts.add(certs[iCnt]);
			}

			CertificateFactory cf = CertificateFactory
					.getInstance(X509_CERT_TYPE);
			CertPath cp = cf.generateCertPath(alCerts);

			return cp.getEncoded(PKCS7_ENCODING);
		} catch (CertificateException ex) {
			throw new CryptoException("NoPkcs7Encode.exception.message", ex);
		}
	}

	public static X509Certificate generateCert(String sCommonName,
			String sOrganisationUnit, String sOrganisation, String sLocality,
			String sState, String sCountryCode, String sEmailAddress,
			int iValidity, PublicKey publicKey, PrivateKey privateKey,
			SignatureType signatureType, String emisor) throws CryptoException,
			JDOMException, CAManagerException, IOException {
		String asunto = "";

		if (sEmailAddress.compareTo("") != 0) {
			asunto = asunto + "E=" + sEmailAddress;
		}
		if (sCountryCode.compareTo("") != 0) {
			asunto = asunto + ", C=" + sCountryCode;
		}

		if (sState.compareTo("") != 0) {
			asunto = asunto + ", ST=" + sState;
		}

		if (sLocality.compareTo("") != 0) {
			asunto = asunto + ", L=" + sLocality;
		}

		if (sOrganisation.compareTo("") != 0) {
			asunto = asunto + ", O=" + sOrganisation;
		}

		if (sOrganisationUnit.compareTo("") != 0) {
			asunto = asunto + ", OU=" + sOrganisationUnit;
		}

		if (sCommonName.compareTo("") != 0) {
			asunto = asunto + ", CN=" + sCommonName;
		}

		if (asunto.charAt(0) == ',') {
			asunto = asunto.substring(1, asunto.length());
		}

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

		certGen.setIssuerDN(new X509Principal(emisor));

		certGen.setNotBefore(new Date(System.currentTimeMillis()));
		certGen.setNotAfter(new Date(System.currentTimeMillis()
				+ ((long) iValidity * 24 * 60 * 60 * 1000)));

		certGen.setSubjectDN(new X509Principal(asunto));

		certGen.setPublicKey(publicKey);

		certGen.setSignatureAlgorithm(signatureType.toString());

		certGen.setSerialNumber(generateX509SerialNumber());

		certGen.addExtension(X509Extensions.BasicConstraints, false,
				new BasicConstraints(false));
		certGen.addExtension(MiscObjectIdentifiers.netscapeCertType, false,
				new NetscapeCertType(NetscapeCertType.sslServer));
		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
				createAuthorityKeyId(publicKey, new X509Name(asunto), 1));

		NetscapeRevocationURL nca = new NetscapeRevocationURL(new DERIA5String(
				ConfigManager.obtenerParametro("CA/URLACTIVA")
						+ "/Repositorio/ultimaCRL.crl"));

		certGen.addExtension(MiscObjectIdentifiers.netscapeRevocationURL,
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

		CRLDistPoint ext = new CRLDistPoint((DistributionPoint[]) distpoints
				.toArray(new DistributionPoint[0]));
		certGen.addExtension(X509Extensions.CRLDistributionPoints.getId(),
				false, ext);

		try {
			X509Certificate cert = certGen.generateX509Certificate(privateKey);

			return cert;
		}

		catch (SignatureException ex) {
			throw new CryptoException("CertificateGenFailed.exception.message",
					ex);
		} catch (InvalidKeyException ex) {
			throw new CryptoException("CertificateGenFailed.exception.message",
					ex);
		}
	}

	public static X509Certificate generateCACert(String sCommonName,
			String sOrganisationUnit1, String sOrganisationUnit2,
			String sOrganisationUnit3, String sOrganisation, String sLocality,
			String sState, String sCountryCode, String sEmailAddress,
			int iValidity, PublicKey publicKey, PrivateKey privateKey,
			SignatureType signatureType, boolean Clase2)
			throws CryptoException, JDOMException, CAManagerException {

		String asunto = "";

		if (sEmailAddress.compareTo("") != 0) {
			asunto = asunto + "E=" + sEmailAddress;
		}
		if (sCountryCode.compareTo("") != 0) {
			asunto = asunto + ", C=" + sCountryCode;
		}

		if (sState.compareTo("") != 0) {
			asunto = asunto + ", ST=" + sState;
		}

		if (sLocality.compareTo("") != 0) {
			asunto = asunto + ", L=" + sLocality;
		}

		if (sOrganisation.compareTo("") != 0) {
			asunto = asunto + ", O=" + sOrganisation;
		}

		if (sOrganisationUnit3.compareTo("") != 0) {
			asunto = asunto + ", OU=" + sOrganisationUnit3;
		}
		if (sOrganisationUnit2.compareTo("") != 0) {
			asunto = asunto + ", OU=" + sOrganisationUnit2;
		}

		if (sOrganisationUnit1.compareTo("") != 0) {
			asunto = asunto + ", OU=" + sOrganisationUnit1;
		}

		if (Clase2) {
			asunto = asunto + ", OU=Autoridad Certificadora Clase 2";
		} else {
			asunto = asunto + ", OU=Autoridad Certificadora Clase 1";
		}

		if (sCommonName.compareTo("") != 0) {
			asunto = asunto + ", CN=" + sCommonName;
		}

		if (asunto.charAt(0) == ',') {
			asunto = asunto.substring(1, asunto.length());
		}

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

		certGen.setIssuerDN(new X509Principal(asunto));

		certGen.setNotBefore(new Date(System.currentTimeMillis()));
		certGen.setNotAfter(new Date(System.currentTimeMillis()
				+ ((long) iValidity * 24 * 60 * 60 * 1000)));

		certGen.setSubjectDN(new X509Principal(asunto));

		certGen.setPublicKey(publicKey);

		certGen.setSignatureAlgorithm(signatureType.toString());

		certGen.setSerialNumber(generateX509SerialNumber());

		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
				createAuthorityKeyId(publicKey, new X509Name(asunto), 1));
		certGen.addExtension(X509Extensions.BasicConstraints, false,
				new BasicConstraints(true));
		certGen.addExtension(MiscObjectIdentifiers.netscapeCertType, false,
				new NetscapeCertType(NetscapeCertType.objectSigningCA
						| NetscapeCertType.smimeCA | NetscapeCertType.sslCA));
		certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
				createSubjectKeyId(publicKey));
		NetscapeRevocationURL nca = new NetscapeRevocationURL(new DERIA5String(
				ConfigManager.obtenerParametro("CA/URLACTIVA")
						+ "/Repositorio/ultimaCRL.crl"));
		certGen.addExtension(MiscObjectIdentifiers.netscapeRevocationURL,
				false, nca);

		certGen.addExtension(X509Extensions.KeyUsage.getId(), false,
				new X509KeyUsage(X509KeyUsage.cRLSign
						| X509KeyUsage.keyCertSign));

		ArrayList distpoints = new ArrayList();
		GeneralName gn = new GeneralName(new DERIA5String(ConfigManager
				.obtenerParametro("CA/URLACTIVA")
				+ "/Repositorio/ultimaCRL.crl"), 6);
		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(gn);
		GeneralNames gns = new GeneralNames(new DERSequence(vec));
		DistributionPointName dpn = new DistributionPointName(0, gns);
		distpoints.add(new DistributionPoint(dpn, null, null));

		CRLDistPoint ext = new CRLDistPoint((DistributionPoint[]) distpoints
				.toArray(new DistributionPoint[0]));
		certGen.addExtension(X509Extensions.CRLDistributionPoints.getId(),
				false, ext);

		try {
			X509Certificate cert = certGen.generateX509Certificate(privateKey);

			return cert;
		}

		catch (SignatureException ex) {
			throw new CryptoException("CertificateGenFailed.exception.message",
					ex);
		} catch (InvalidKeyException ex) {
			throw new CryptoException("CertificateGenFailed.exception.message",
					ex);
		}
	}

	private static BigInteger generateX509SerialNumber() {

		return new BigInteger(Long.toString(System.currentTimeMillis() / 1000));
	}

	public static String generatePKCS10CSR(X509Certificate cert,
			PrivateKey privateKey) throws CryptoException {
		X509Name subject = new X509Name(cert.getSubjectDN().toString());

		try {
			PKCS10CertificationRequest csr = new PKCS10CertificationRequest(
					cert.getSigAlgName(), subject, cert.getPublicKey(), null,
					privateKey);
			if (!csr.verify()) {
				throw new CryptoException("NoVerifyGenCsr.exception.message");
			}

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DEROutputStream deros = new DEROutputStream(baos);
			deros.writeObject(csr.getDERObject());
			String sTmp = new String(Base64.encode(baos.toByteArray()));

			String sCsr = BEGIN_CERT_REQ + "\n";

			for (int iCnt = 0; iCnt < sTmp.length(); iCnt += CERT_REQ_LINE_LENGTH) {
				int iLineLength;

				if ((iCnt + CERT_REQ_LINE_LENGTH) > sTmp.length()) {
					iLineLength = (sTmp.length() - iCnt);
				} else {
					iLineLength = CERT_REQ_LINE_LENGTH;
				}

				sCsr += sTmp.substring(iCnt, (iCnt + iLineLength)) + "\n";
			}

			sCsr += END_CERT_REQ + "\n";

			return sCsr;
		} catch (NoSuchProviderException ex) {
			throw new CryptoException("NoGenerateCsr.exception.message", ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException("NoGenerateCsr.exception.message", ex);
		} catch (SignatureException ex) {
			throw new CryptoException("NoGenerateCsr.exception.message", ex);
		} catch (InvalidKeyException ex) {
			throw new CryptoException("NoGenerateCsr.exception.message", ex);
		} catch (IOException ex) {
			throw new CryptoException("NoGenerateCsr.exception.message", ex);
		}
	}

	public static boolean verifyCertificate(X509Certificate signedCert,
			X509Certificate signingCert) throws CryptoException {
		try {
			signedCert.verify(signingCert.getPublicKey());
		}

		catch (InvalidKeyException ex) {
			return false;
		}

		catch (SignatureException ex) {
			return false;
		}

		catch (NoSuchProviderException ex) {
			throw new CryptoException("NoVerifyCertificate.exception.message",
					ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException("NoVerifyCertificate.exception.message",
					ex);
		} catch (CertificateException ex) {
			throw new CryptoException("NoVerifyCertificate.exception.message",
					ex);
		}
		return true;
	}

	public static X509Certificate[] establishTrust(KeyStore keyStores[],
			X509Certificate cert) throws CryptoException {

		Vector ksCerts = new Vector();
		for (int iCnt = 0; iCnt < keyStores.length; iCnt++) {
			ksCerts.addAll(extractCertificates(keyStores[iCnt]));
		}

		return establishTrust(ksCerts, cert);
	}

	private static X509Certificate[] establishTrust(Vector vCompCerts,
			X509Certificate cert) throws CryptoException {

		for (int iCnt = 0; iCnt < vCompCerts.size(); iCnt++) {
			X509Certificate compCert = (X509Certificate) vCompCerts.get(iCnt);

			if (cert.getIssuerDN().equals(compCert.getSubjectDN())) {

				if (X509CertUtil.verifyCertificate(cert, compCert)) {

					if (compCert.getSubjectDN().equals(compCert.getIssuerDN())) {
						return new X509Certificate[] { cert, compCert };
					}

					else {
						X509Certificate[] tmpChain = establishTrust(vCompCerts,
								compCert);
						if (tmpChain != null) {
							X509Certificate[] trustChain = new X509Certificate[tmpChain.length + 1];

							trustChain[0] = cert;

							for (int iCntInr = 1; iCntInr <= tmpChain.length; iCntInr++) {
								trustChain[iCntInr] = tmpChain[iCntInr - 1];
							}

							return trustChain;
						}
					}
				}
			}
		}

		return null;
	}

	private static Vector extractCertificates(KeyStore keyStore)
			throws CryptoException {
		try {

			Enumeration enum1 = keyStore.aliases();

			Vector vCerts = new Vector();

			while (enum1.hasMoreElements()) {
				String sAlias = (String) enum1.nextElement();

				if (keyStore.isCertificateEntry(sAlias)) {
					vCerts.add(X509CertUtil.convertCertificate(keyStore
							.getCertificate(sAlias)));
				}
			}

			return vCerts;
		} catch (KeyStoreException ex) {
			throw new CryptoException(
					"NoExtractCertificates.exception.message", ex);
		}
	}

	public static String matchCertificate(KeyStore keyStore,
			X509Certificate cert) throws CryptoException {
		try {
			Enumeration enum1 = keyStore.aliases();

			while (enum1.hasMoreElements()) {
				String sAlias = (String) enum1.nextElement();
				if (keyStore.isCertificateEntry(sAlias)) {
					X509Certificate compCert = X509CertUtil
							.convertCertificate(keyStore.getCertificate(sAlias));

					if (cert.equals(compCert)) {
						return sAlias;
					}
				}
			}
			return null;
		} catch (KeyStoreException ex) {
			throw new CryptoException("NoMatchCertificate.exception.message",
					ex);
		}
	}

	public static String getCertificateAlias(X509Certificate cert) {

		Principal subject = cert.getSubjectDN();
		Principal issuer = cert.getIssuerDN();

		String sSubject = subject.getName();
		String sSubjectCN = "";
		int iCN = sSubject.indexOf("CN=");
		if (iCN != -1) {
			iCN += 3;
			int iEndCN = sSubject.indexOf(", ", iCN);
			if (iEndCN != -1) {
				sSubjectCN = sSubject.substring(iCN, iEndCN).toLowerCase();
			} else {
				sSubjectCN = sSubject.substring(iCN).toLowerCase();
			}
		}

		String sIssuer = issuer.getName();
		String sIssuerCN = "";
		iCN = sIssuer.indexOf("CN=");
		if (iCN != -1) {
			iCN += 3;
			int iEndCN = sIssuer.indexOf(", ", iCN);
			if (iEndCN != -1) {
				sIssuerCN = sIssuer.substring(iCN, iEndCN).toLowerCase();
			} else {
				sIssuerCN = sIssuer.substring(iCN).toLowerCase();
			}
		}

		if (sSubjectCN.length() == 0) {
			return "";
		}

		if ((subject.equals(issuer)) || (sIssuerCN.length() == 0)) {

			return sSubjectCN;
		}

		else {

			return MessageFormat.format("{0} ({1})", new String[] { sSubjectCN,
					sIssuerCN });
		}
	}

	public static int getCertificateKeyLength(X509Certificate cert)
			throws CryptoException {
		try {

			PublicKey pubKey = cert.getPublicKey();

			String sAlgorithm = pubKey.getAlgorithm();

			if (sAlgorithm.equals(KeyPairType.RSA.toString())) {
				KeyFactory keyFact = KeyFactory.getInstance(sAlgorithm);
				RSAPublicKeySpec keySpec = (RSAPublicKeySpec) keyFact
						.getKeySpec(pubKey, RSAPublicKeySpec.class);
				BigInteger modulus = keySpec.getModulus();
				return modulus.toString(2).length();
			} else if (sAlgorithm.equals(KeyPairType.DSA.toString())) {
				KeyFactory keyFact = KeyFactory.getInstance(sAlgorithm);
				DSAPublicKeySpec keySpec = (DSAPublicKeySpec) keyFact
						.getKeySpec(pubKey, DSAPublicKeySpec.class);
				BigInteger prime = keySpec.getP();
				return prime.toString(2).length();
			}

			else {
				throw new CryptoException(
						MessageFormat
								.format(
										"NoCertificatePublicKeysizeUnrecogAlg.exception.message",
										new Object[] { sAlgorithm }));
			}
		} catch (GeneralSecurityException ex) {
			throw new CryptoException(
					"NoCertificatePublicKeysize.exception.message", ex);
		}
	}

	public static AuthorityKeyIdentifier createAuthorityKeyId(PublicKey pubKey,
			X509Name name, int sNumber) {
		try {
			ByteArrayInputStream bIn = new ByteArrayInputStream(pubKey
					.getEncoded());
			SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
					(ASN1Sequence) new DERInputStream(bIn).readObject());

			GeneralName genName = new GeneralName(name);
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(genName);

			return new AuthorityKeyIdentifier(info, new GeneralNames(
					new DERSequence(v)), BigInteger.valueOf(sNumber));
		} catch (Exception e) {
			throw new RuntimeException("error creating AuthorityKeyId");
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
			throw new RuntimeException("error creating key");
		}
	}

	public static X509Certificate renovarCACert(X509Certificate cacert,
			PrivateKey privateKey, int validez) throws CryptoException,
			JDOMException, CAManagerException {

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

		certGen.setIssuerDN(new X509Principal(cacert.getIssuerDN().toString()));

		certGen.setNotBefore(new Date(System.currentTimeMillis()));
		certGen.setNotAfter(new Date(System.currentTimeMillis()
				+ ((long) validez * 24 * 60 * 60 * 1000)));

		certGen
				.setSubjectDN(new X509Principal(cacert.getSubjectDN()
						.toString()));

		certGen.setPublicKey(cacert.getPublicKey());

		certGen.setSignatureAlgorithm(cacert.getSigAlgName());

		certGen.setSerialNumber(generateX509SerialNumber());

		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
				createAuthorityKeyId(cacert.getPublicKey(), new X509Name(cacert
						.getIssuerDN().toString()), 1));
		certGen.addExtension(X509Extensions.BasicConstraints, false,
				new BasicConstraints(true));
		certGen.addExtension(MiscObjectIdentifiers.netscapeCertType, false,
				new NetscapeCertType(NetscapeCertType.objectSigningCA
						| NetscapeCertType.smimeCA | NetscapeCertType.sslCA));
		certGen.addExtension(X509Extensions.SubjectKeyIdentifier, true,
				createSubjectKeyId(cacert.getPublicKey()));
		NetscapeRevocationURL nca = new NetscapeRevocationURL(new DERIA5String(
				ConfigManager.obtenerParametro("CA/URLACTIVA")
						+ "/Repositorio/ultimaCRL.crl"));
		certGen.addExtension(MiscObjectIdentifiers.netscapeRevocationURL, true,
				nca);

		certGen.addExtension(X509Extensions.KeyUsage.getId(), true,
				new X509KeyUsage(X509KeyUsage.cRLSign
						| X509KeyUsage.keyCertSign));

		try {
			X509Certificate cert = certGen.generateX509Certificate(privateKey);

			return cert;
		}

		catch (SignatureException ex) {
			throw new CryptoException("CertificateGenFailed.exception.message",
					ex);
		} catch (InvalidKeyException ex) {
			throw new CryptoException("CertificateGenFailed.exception.message",
					ex);
		}
	}

}
