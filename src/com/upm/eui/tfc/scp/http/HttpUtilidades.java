package com.upm.eui.tfc.scp.http;

import java.util.*;

/**
 * Clase encargada de encapsular distintos metodos utiles para el cliente de
 * HTTP.
 * 
 * @version 1.0
 */

public class HttpUtilidades {
	final static String version = "1.0";
	final static String mime_text_plain = "text/plain";
	final static String mime_text_html = "text/html; charset=utf-8";
	final static String mime_text_xml = "text/xml";
	final static String mime_text_xsl = "text/xml";
	final static String mime_text_css = "text/css";
	final static String mime_image_gif = "image/gif";
	final static String mime_cert_ca = "aplication/gif";
	final static String mime_image_jpg = "image/jpg";
	final static String mime_app_os = "application/octet-stream";
	final static String mime_app_ca = "application/x-x509-ca-cert";
	final static String mime_app_cert = "application/octet-stream";
	final static String mime_app_crl = "application/pkcs-crl";
	final static String mime_multi_mixed = "multipart/mixed; boundary=\"===== boundary =====1234567890987654321\"";
	final static String CRLF = "\r\n";

	public static byte aBytes(String s)[] {
		byte b[] = new byte[s.length()];
		s.getBytes(0, b.length, b, 0);
		return (b);
	}

	public static byte concatenarBytes(byte a[], byte b[])[] {
		byte ret[] = new byte[a.length + b.length];
		System.arraycopy(a, 0, ret, 0, a.length);
		System.arraycopy(b, 0, ret, a.length, b.length);
		return (ret);
	}

	public static byte cabMime(String ct, int tam)[] {
		return (cabMime(200, "OK", ct, tam));
	}

	public static byte cabMime(int codigo, String mensaje, String ct, int tam)[] {
		Date d = new Date();
		return (aBytes("HTTP/1.1 " + codigo + " " + mensaje + CRLF + "Date: "
				+ d.toGMTString() + CRLF + "Server: Java/" + version + CRLF
				+ "Content-type: " + ct + CRLF
				+ (tam > 0 ? "Content-length: " + tam + CRLF : "") + CRLF));
	}

	public static byte error(int codigo, String msg, String fname)[] {
		String ret = "<BODY>" + CRLF + "<H1>" + codigo + " " + msg + "</H1>"
				+ CRLF;

		if (fname != null)
			ret += "Error al buscar el URL: " + fname + CRLF;
		ret += "</BODY>" + CRLF;
		byte tmp[] = cabMime(codigo, msg, mime_text_html, 0);
		return (concatenarBytes(tmp, aBytes(ret)));
	}

	public static String mimeTypeString(String fichero) {
		String tipo;

		if (fichero.endsWith(".html") || fichero.endsWith(".htm"))
			tipo = mime_text_html;
		else if (fichero.endsWith(".class"))
			tipo = mime_app_os;
		else if (fichero.endsWith(".gif"))
			tipo = mime_image_gif;
		else if (fichero.endsWith(".jpg"))
			tipo = mime_image_jpg;
		else if (fichero.endsWith(".xml"))
			tipo = mime_text_xml;
		else if (fichero.endsWith(".xsl"))
			tipo = mime_text_xsl;
		else if (fichero.endsWith(".css"))
			tipo = mime_text_css;
		else if (fichero.endsWith(".crt"))
			tipo = mime_app_ca;
		else if (fichero.endsWith(".crl"))
			tipo = mime_app_crl;
		else if (fichero.endsWith(".cer"))
			tipo = mime_app_cert;
		else if (fichero.endsWith(".mix"))
			tipo = mime_multi_mixed;
		else
			tipo = mime_text_plain;
		return (tipo);
	}
}
