package com.upm.eui.tfc.scp.consola;

import java.awt.Dimension;
import java.awt.Toolkit;

import javax.swing.UIManager;

/**
 * Clase encargada de ejecutar e inicializar el GUI desde donde el administrador
 * del sistema podra gestionar el servicio correspondiente a la Autoridad
 * Certificadora.
 * 
 * @version 1.0
 */

public class consolaCA {
	boolean packFrame = false;

	public consolaCA() {
		consolaCAMarco frame = new consolaCAMarco();

		if (packFrame) {
			frame.pack();
		} else {
			frame.validate();
		}

		Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
		Dimension frameSize = frame.getSize();
		if (frameSize.height > screenSize.height) {
			frameSize.height = screenSize.height;
		}
		if (frameSize.width > screenSize.width) {
			frameSize.width = screenSize.width;
		}
		frame.setLocation((screenSize.width - frameSize.width) / 2,
				(screenSize.height - frameSize.height) / 2);
		frame.setVisible(true);
	}

	public static void inicializar() {
		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		} catch (Exception e) {
			e.printStackTrace();
		}
		new consolaCA();
	}
}
