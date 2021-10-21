package com.upm.eui.tfc.scp.manager;

import java.io.File;

/**
 * Clase encargada de gestionar los permisos de los ficheros servidos por el
 * cliente HTTP. Evita accesos no permitidos a ficheros del sistema sobre el
 * cual se esta ejecutando la aplicacion y permite si se desea a–adir
 * restricciones en funcion de distintos criterios de seguridad.
 * 
 * @version 1.0
 */

public class SecurityFileManager {

	File f = null;

	public SecurityFileManager() {
	}

	public boolean obtenerFichero(String peticion) {
		if (peticion.indexOf("..") != -1) {
			return false;
		} else {
			f = new File(peticion);
			if (f != null) {
				return true;
			} else {
				return false;
			}
		}
	}

}
