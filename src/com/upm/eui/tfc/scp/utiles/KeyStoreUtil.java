package com.upm.eui.tfc.scp.utiles;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.text.MessageFormat;

/**
 * Clase que encapsula distintos metodos y procedimientos utiles para el manejo
 * de almacenes de certificados digitales.
 * 
 * @version 1.0
 */

public final class KeyStoreUtil extends Object {
	private KeyStoreUtil() {
	}

	public static KeyStore createKeyStore(KeyStoreType keyStoreType)
			throws CryptoException, IOException {
		KeyStore keyStore = null;

		try {
			if ((keyStoreType == KeyStoreType.PKCS12)
					|| (keyStoreType == KeyStoreType.BKS)
					|| (keyStoreType == KeyStoreType.UBER)) {
				if (Security.getProvider("BC") == null) {
					throw new CryptoException("NoBcProvider.exception.message");
				}
				keyStore = KeyStore.getInstance(keyStoreType.toString(), "BC");
			} else {
				keyStore = KeyStore.getInstance(keyStoreType.toString());
			}
			keyStore.load(null, null);
		} catch (KeyStoreException ex) {
			throw new CryptoException("NoCreateKeystore.exception.message", ex);
		} catch (CertificateException ex) {
			throw new CryptoException("NoCreateKeystore.exception.message", ex);
		} catch (NoSuchProviderException ex) {
			throw new CryptoException("NoCreateKeystore.exception.message", ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException("NoCreateKeystore.exception.message", ex);
		}

		return keyStore;
	}

	public static KeyStore loadKeyStore(File fKeyStore, char[] cPassword,
			KeyStoreType keyStoreType) throws CryptoException,
			FileNotFoundException {
		FileInputStream fis = new FileInputStream(fKeyStore);

		KeyStore keyStore = null;
		try {
			if ((keyStoreType == KeyStoreType.PKCS12)
					|| (keyStoreType == KeyStoreType.BKS)
					|| (keyStoreType == KeyStoreType.UBER)) {
				if (Security.getProvider("BC") == null) {
					throw new CryptoException("NoBcProvider.exception.message");
				}

				keyStore = KeyStore.getInstance(keyStoreType.toString(), "BC");
			} else {
				keyStore = KeyStore.getInstance(keyStoreType.toString());
			}
		} catch (KeyStoreException ex) {
			throw new CryptoException("NoCreateKeystore.exception.message", ex);
		} catch (NoSuchProviderException ex) {
			throw new CryptoException("NoCreateKeystore.exception.message", ex);
		}

		try {
			keyStore.load(fis, cPassword);
		} catch (CertificateException ex) {
			throw new CryptoException(MessageFormat.format(
					"NoLoadKeystore.exception.message",
					new Object[] { keyStoreType }), ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException(MessageFormat.format(
					"NoLoadKeystore.exception.message",
					new Object[] { keyStoreType }), ex);
		} catch (FileNotFoundException ex) {
			throw ex;
		} catch (IOException ex) {
			throw new CryptoException(MessageFormat.format(
					"NoLoadKeystore.exception.message",
					new Object[] { keyStoreType }), ex);
		}

		try {
			fis.close();
		} catch (IOException ex) { /* Ignore */
		}

		return keyStore;
	}

	public static void saveKeyStore(KeyStore keyStore, File fKeyStoreFile,
			char[] cPassword) throws CryptoException, FileNotFoundException,
			IOException {
		FileOutputStream fos = null;

		fos = new FileOutputStream(fKeyStoreFile);

		try {
			keyStore.store(fos, cPassword);
		} catch (IOException ex) {
			throw new CryptoException("NoSaveKeystore.exception.message", ex);
		} catch (KeyStoreException ex) {
			throw new CryptoException("NoSaveKeystore.exception.message", ex);
		} catch (CertificateException ex) {
			throw new CryptoException("NoSaveKeystore.exception.message", ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException("NoSaveKeystore.exception.message", ex);
		} 

		fos.close();
	}
}
