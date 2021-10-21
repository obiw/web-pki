package com.upm.eui.tfc.scp.utiles;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.MessageFormat;

/**
 * Clase que encapsula distintos metodos y procedimientos utiles para el manejo
 * de claves asimetricas.
 * 
 * @version 1.0
 */

public final class KeyPairUtil extends Object {

	private KeyPairUtil() {
	}

	public static KeyPair generateKeyPair(KeyPairType keyPairType, int iKeySize)
			throws CryptoException {
		try {

			KeyPairGenerator keyPairGen = KeyPairGenerator
					.getInstance(keyPairType.toString());

			SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");

			keyPairGen.initialize(iKeySize, rand);

			KeyPair keyPair = keyPairGen.generateKeyPair();
			return keyPair;
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException(MessageFormat.format(
					"NoGenerateKeypair.exception.message",
					new Object[] { keyPairType }), ex);
		}
	}
}
