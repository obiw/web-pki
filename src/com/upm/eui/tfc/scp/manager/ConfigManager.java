package com.upm.eui.tfc.scp.manager;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;

import com.upm.eui.tfc.scp.excep.CAManagerException;

/**
 * Clase encargada de gestionar el fichero de configuracion de la aplicacion.
 * Para evitar inconsistencias que pudieran ser provocadas por multiples accesos
 * al fichero de configuracion esta clase recubre dicho fichero y ofrece metodos
 * para leer y escribir distintos parametros de configuracion.
 * 
 * @version 1.0
 */

public class ConfigManager {

	private static SAXBuilder builder = null;
	private static Document reg = null;
	private static XMLOutputter out = null;

	public static String obtenerParametro(String parametro)
			throws CAManagerException, JDOMException {
		String[] aux = null;
		Element ele = null;
		builder = new SAXBuilder();
		File fconf = new File("conf/configuracion.xml");

		reg = builder.build(fconf);
		aux = parametro.split("/");
		ele = reg.getRootElement().getChild(aux[0]);
		for (int i = 1; i < aux.length; i++) {
			ele = ele.getChild(aux[i]);
		}
		return ele.getText();
	}

	public static void guardarParametro(String parametro, String valor)
			throws CAManagerException, JDOMException, CAManagerException,
			IOException {
		String[] aux = null;
		Element ele = null;
		builder = new SAXBuilder();
		File fconf = new File("conf/configuracion.xml");
		FileOutputStream fos = null;
		out = new XMLOutputter();

		reg = builder.build(fconf);
		aux = parametro.split("/");
		ele = reg.getRootElement().getChild(aux[0]);
		for (int i = 1; i < aux.length; i++) {
			ele = ele.getChild(aux[i]);
		}
		ele.setText(valor);

		fos = new FileOutputStream(fconf);
		out.output(reg, fos);
		fos.close();
	}

}
