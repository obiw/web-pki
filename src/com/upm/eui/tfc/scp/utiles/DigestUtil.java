package com.upm.eui.tfc.scp.utiles;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Clase que encapsula distintos metodos y procedimientos utiles para el manejo
 * de algoritmos de resumenes.
 * 
 * @version 1.0
 */

public final class DigestUtil extends Object {

	private DigestUtil() {
	}

	public static String getMessageDigest(byte[] bMessage, DigestType digestType)
			throws CryptoException {
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance(digestType.toString());
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoException("NoCreateDigest.exception.message", ex);
		}

		byte[] bFingerPrint = messageDigest.digest(bMessage);

		StringBuffer strBuff = new StringBuffer(new BigInteger(1, bFingerPrint)
				.toString(16).toUpperCase());

		if ((strBuff.length() % 2) == 1) {
			strBuff.insert(0, '0');
		}

		if (strBuff.length() > 2) {
			for (int iCnt = 2; iCnt < strBuff.length(); iCnt += 3) {
				strBuff.insert(iCnt, ':');
			}
		}

		return strBuff.toString();
	}
}
