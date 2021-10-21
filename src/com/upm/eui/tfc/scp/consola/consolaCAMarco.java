package com.upm.eui.tfc.scp.consola;

import java.awt.AWTEvent;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Rectangle;
import java.awt.SystemColor;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.util.Date;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.border.TitledBorder;

import org.jdom.JDOMException;

import com.upm.eui.tfc.scp.excep.CAManagerException;
import com.upm.eui.tfc.scp.http.HttpServer;
import com.upm.eui.tfc.scp.http.HttpsServer;
import com.upm.eui.tfc.scp.manager.ConfigManager;
import com.upm.eui.tfc.scp.manager.LogManager;
import com.upm.eui.tfc.scp.manager.RAManager;

/**
 * This code was edited or generated using CloudGarden's Jigloo
 * SWT/Swing GUI Builder, which is free for non-commercial
 * use. If Jigloo is being used commercially (ie, by a corporation,
 * company or business for any purpose whatever) then you
 * should purchase a license for each developer using Jigloo.
 * Please visit www.cloudgarden.com for details.
 * Use of Jigloo implies acceptance of these licensing terms.
 * A COMMERCIAL LICENSE HAS NOT BEEN PURCHASED FOR
 * THIS MACHINE, SO JIGLOO OR THIS CODE CANNOT BE USED
 * LEGALLY FOR ANY CORPORATE OR COMMERCIAL PURPOSE.
 */
/**
 * Clase encargada de generar el GUI para la gestion de consola de la Autoridad
 * Certificadora. Permitira levantar el servicio asi como detenerlo y mostrara
 * un log de actividad al administrador.
 * 
 * @version 1.0
 */

public class consolaCAMarco extends JFrame {

	{
		// Set Look & Feel
		try {
			javax.swing.UIManager.setLookAndFeel("apple.laf.AquaLookAndFeel");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static final long serialVersionUID = 1L;
	private RAManager ra = new RAManager();
	JPanel contentPane;
	private JButton jRenovarCASSL;
	private JButton jRenovarCA;
	JButton jarrancar = new JButton();
	JButton jdetener = new JButton();
	HttpsServer https = null;
	HttpServer http = null;
	JPanel jPanel1 = new JPanel();
	TitledBorder titledBorder1;
	TitledBorder titledBorder2;
	TitledBorder titledBorder3;
	TitledBorder titledBorder4;
	JLabel jestado = new JLabel();
	TitledBorder titledBorder5;
	JScrollPane jScrollPane1 = new JScrollPane();
	JTextArea jlog = new JTextArea();

	public consolaCAMarco() {
		enableEvents(AWTEvent.WINDOW_EVENT_MASK);
		try {
			jbInit();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void jbInit() throws Exception {
		contentPane = (JPanel) this.getContentPane();
		titledBorder1 = new TitledBorder("");
		titledBorder2 = new TitledBorder("");
		titledBorder3 = new TitledBorder("");
		titledBorder4 = new TitledBorder("");
		titledBorder5 = new TitledBorder("");
		jarrancar.setBounds(718, 20, 118, 29);
		jarrancar.setFont(new java.awt.Font("Verdana", 1, 12));
		jarrancar.setText("Arrancar");
		jarrancar.addActionListener(new consolaCAMarco_jarrancar_actionAdapter(
				this));
		contentPane.setLayout(null);
		this.setResizable(false);
		this.setSize(new Dimension(977, 476));
		this.setTitle("Consola de Administracion");
		jdetener.setBounds(840, 19, 119, 30);
		jdetener.setEnabled(false);
		jdetener.setFont(new java.awt.Font("Verdana", 1, 12));
		jdetener.setText("Detener");
		jdetener.addActionListener(new consolaCAMarco_jdetener_actionAdapter(
				this));
		jPanel1.setBorder(titledBorder2);
		jPanel1.setOpaque(false);
		jPanel1.setBounds(new Rectangle(21, 13, 431, 46));
		jPanel1.setLayout(null);
		contentPane.setEnabled(true);
		contentPane.setPreferredSize(new Dimension(1, 1));
		jestado.setBackground(SystemColor.desktop);
		jestado.setFont(new java.awt.Font("Verdana", 1, 12));
		jestado.setForeground(Color.red);
		jestado.setText("DETENIDA...");
		jestado.setBounds(new Rectangle(12, 11, 268, 23));
		jScrollPane1.setBounds(new Rectangle(8, 71, 951, 375));
		jlog.setFont(new java.awt.Font("Verdana", 0, 10));
		jlog.setBorder(titledBorder5);
		jlog.setWrapStyleWord(false);
		jlog.setAutoscrolls(true);
		jlog.setColumns(1);
		contentPane.add(jPanel1, null);
		jPanel1.add(jestado, null);
		contentPane.add(jScrollPane1, null);
		contentPane.add(jdetener, null);
		contentPane.add(jarrancar, null);
		{
			jRenovarCA = new JButton();
			contentPane.add(jRenovarCA);
			jRenovarCA.setText("Renovar CA");
			jRenovarCA.setBounds(459, 20, 120, 29);
			jRenovarCA.setFont(new java.awt.Font("Verdana", 1, 12));
			jRenovarCA.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent evt) {
					jRenovarCAActionPerformed(evt);
				}
			});
		}
		{
			jRenovarCASSL = new JButton();
			contentPane.add(jRenovarCASSL);
			jRenovarCASSL.setText("Renovar SSL");
			jRenovarCASSL.setBounds(583, 20, 131, 29);
			jRenovarCASSL.setFont(new java.awt.Font("Verdana", 1, 12));
			jRenovarCASSL.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent evt) {
					jRenovarCASSLActionPerformed(evt);
				}
			});
		}
		jScrollPane1.getViewport().add(jlog, null);
	}

	protected void processWindowEvent(WindowEvent e) {
		super.processWindowEvent(e);
		if (e.getID() == WindowEvent.WINDOW_CLOSING) {
			System.exit(0);
		}
	}

	void jarrancar_actionPerformed(ActionEvent e) {
		String pass1 = "";
		String pass2 = "";
		File f = null;
		LogManager log = null;
		String fecha = "";

		JPasswordField pwd1 = new JPasswordField(10);
		JPasswordField pwd2 = new JPasswordField(10);
		pwd1.setFocusable(true);
		pwd2.setFocusable(true);
		int action = JOptionPane.showConfirmDialog(null, pwd1,
				"Primera contraseña", JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.QUESTION_MESSAGE);
		if (action == 0) {
			pass1 = new String(pwd1.getPassword());
			action = JOptionPane.showConfirmDialog(null, pwd2,
					"Segunda contraseña", JOptionPane.OK_CANCEL_OPTION,
					JOptionPane.QUESTION_MESSAGE);
			if (action == 0) {
				pass2 = new String(pwd2.getPassword());

				try {
					Date d = new Date();

					fecha = d.getDay() + "-" + d.getMonth() + "-" + d.getYear();
					f = new File(ConfigManager
							.obtenerParametro("INSTALACION/DIRECTORIO")
							+ "/log/scp-" + fecha + ".log");
					log = new LogManager(jlog, f);
					log
							.log("Arrancando la CA en: "
									+ ConfigManager
											.obtenerParametro("CA/URLACTIVA"),
									0);
					if (ConfigManager.obtenerParametro("SERVIDOR/SSL/ACTIVADO")
							.compareToIgnoreCase("S") == 0) {
						https = new HttpsServer(pass1, pass2, log, ra);
					} else {
						http = new HttpServer(pass1, pass2, log, ra);
					}
					jestado.setForeground(Color.GREEN);
					jestado.setText("ARRANCADA...");
					jarrancar.setEnabled(false);
					jdetener.setEnabled(true);
				} catch (Exception ex) {
					JOptionPane.showMessageDialog(contentPane,
							"Ocurrio el siguiente error: \n" + ex.getMessage(),
							"Error", JOptionPane.ERROR_MESSAGE);
				}
			}
		}
	}

	void jdetener_actionPerformed(ActionEvent e) {
		try {
			if (ConfigManager.obtenerParametro("SERVIDOR/SSL/ACTIVADO")
					.compareToIgnoreCase("S") == 0) {
				https.detener();
			} else {
				http.detener();
			}
			jestado.setForeground(Color.red);
			jestado.setText("DETENIDA...");
			jarrancar.setEnabled(true);
			jdetener.setEnabled(false);

		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private void jRenovarCAActionPerformed(ActionEvent evt) {
		File f = null;
		LogManager log = null;
		String fecha = "";
		String pass1 = null, pass2 = null;
		int dias = 0;
		JTextField validez = new JTextField(10);
		validez.setFocusable(true);
		int action1 = JOptionPane.showConfirmDialog(null, validez,
				"Nueva validez (dias)", JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.QUESTION_MESSAGE);
		if (action1 == 0) {
			fecha = new String(validez.getText());
			try {
				dias = Integer.parseInt(fecha);
				if (dias > 0) {
					try {
						JPasswordField pwd1 = new JPasswordField(10);
						JPasswordField pwd2 = new JPasswordField(10);
						pwd1.setFocusable(true);
						pwd2.setFocusable(true);
						int action2 = JOptionPane.showConfirmDialog(null, pwd1,
								"Primera contraseña",
								JOptionPane.OK_CANCEL_OPTION,
								JOptionPane.QUESTION_MESSAGE);
						if (action2 == 0) {
							pass1 = new String(pwd1.getPassword());
							action2 = JOptionPane.showConfirmDialog(null, pwd2,
									"Segunda contraseña",
									JOptionPane.OK_CANCEL_OPTION,
									JOptionPane.QUESTION_MESSAGE);
							if (action2 == 0) {
								pass2 = new String(pwd2.getPassword());

								try {
									Date d = new Date();

									String fechalog = d.getDay() + "-"
											+ d.getMonth() + "-" + d.getYear();
									f = new File(
											ConfigManager
													.obtenerParametro("INSTALACION/DIRECTORIO")
													+ "/log/scp-"
													+ fechalog
													+ ".log");
									log = new LogManager(jlog, f);
									log.log(
											"Renovando la CA con nuevo tiempo de validez: "
													+ fecha + " (dias)", 0);
									if (ra.renovarCA(pass1.toCharArray(), pass2
											.toCharArray(), Integer
											.parseInt(fecha))) {
										JOptionPane
												.showMessageDialog(
														contentPane,
														"La CA se renovo correctamente. Los nuevos certificados ya se encuentran publicados en el repositorio.",
														"Exito",
														JOptionPane.INFORMATION_MESSAGE);
										log
												.log(
														"Certificado de CA renovado correctamente.",
														0);
									} else {
										JOptionPane.showMessageDialog(
												contentPane, ra.getLastError(),
												"Error",
												JOptionPane.ERROR_MESSAGE);
										log
												.log(
														"Error al renovar el certificado de CA.",
														2);
									}
								} catch (Exception ex) {
									JOptionPane.showMessageDialog(contentPane,
											"Ocurrio el siguiente error: \n"
													+ ex.getMessage(), "Error",
											JOptionPane.ERROR_MESSAGE);
									log
											.log(
													"Error al renovar el certificado de CA.",
													2);
								}
							}
						}

					} catch (Exception ex) {
						JOptionPane.showMessageDialog(contentPane,
								"Ocurrio el siguiente error: \n"
										+ ex.getMessage(), "Error",
								JOptionPane.ERROR_MESSAGE);
						log.log("Error al renovar el certificado de CA.", 2);
					}
				} else {
					JOptionPane.showMessageDialog(contentPane,
							"El tiempo de validez debe ser mayor que 0.",
							"Error", JOptionPane.ERROR_MESSAGE);
					log.log("Error al renovar el certificado de CA.", 2);
				}
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(contentPane,
						"El tiempo de validez debe ser un valor numerico.",
						"Error", JOptionPane.ERROR_MESSAGE);
				log.log("Error al renovar el certificado de CA.", 2);
			}

		}
	}

	private void jRenovarCASSLActionPerformed(ActionEvent evt) {
		int action;
		LogManager log = null;

		try {
			if (ConfigManager.obtenerParametro("SERVIDOR/SSL/ACTIVADO")
					.compareToIgnoreCase("S") == 0) {
				action = JOptionPane
						.showConfirmDialog(
								null,
								"El certificado utilizado para levantar el interfaz web con HTTPS sera renovado por un año.\n¿Desea proceder con al renovacion?");
				if (action == 0) {

					try {
						JPasswordField pwd1 = new JPasswordField(10);
						JPasswordField pwd2 = new JPasswordField(10);
						pwd1.setFocusable(true);
						pwd2.setFocusable(true);
						String pass1 = "", pass2 = "";
						int action2 = JOptionPane.showConfirmDialog(null, pwd1,
								"Primera contraseña",
								JOptionPane.OK_CANCEL_OPTION,
								JOptionPane.QUESTION_MESSAGE);
						if (action2 == 0) {
							pass1 = new String(pwd1.getPassword());
							action2 = JOptionPane.showConfirmDialog(null, pwd2,
									"Segunda contraseña",
									JOptionPane.OK_CANCEL_OPTION,
									JOptionPane.QUESTION_MESSAGE);
							if (action2 == 0) {
								pass2 = new String(pwd2.getPassword());

								try {
									Date d = new Date();

									String fechalog = d.getDay() + "-"
											+ d.getMonth() + "-" + d.getYear();
									File f = new File(
											ConfigManager
													.obtenerParametro("INSTALACION/DIRECTORIO")
													+ "/log/scp-"
													+ fechalog
													+ ".log");
									log = new LogManager(jlog, f);
									log
											.log(
													"Renovando el certificado para HTTPS del interfaz web.",
													0);
									if (ra.renovarCAWebSSL(pass1.toCharArray(),
											pass2.toCharArray())) {
										JOptionPane
												.showMessageDialog(
														contentPane,
														"El certificado para HTTPS del interfaz web fue renovado con exito.",
														"Exito",
														JOptionPane.INFORMATION_MESSAGE);
										log
												.log(
														"El certificado para HTTPS del interfaz web fue renovado con exito. Para utilizar el nuevo certificado es necesario reinciar el interfaz web.",
														0);

									} else {
										JOptionPane.showMessageDialog(
												contentPane, ra.getLastError(),
												"Error",
												JOptionPane.ERROR_MESSAGE);
										log
												.log(
														"Se produjo un error al intentar renovar el certificado para HTTPS del interfaz web.",
														0);
									}
								} catch (Exception ex) {
									JOptionPane.showMessageDialog(contentPane,
											"Ocurrio el siguiente error: \n"
													+ ex.getMessage(), "Error",
											JOptionPane.ERROR_MESSAGE);
									log
											.log(
													"Se produjo un error al intentar renovar el certificado para HTTPS del interfaz web.",
													2);
								}
							}
						}

					} catch (Exception ex) {
						JOptionPane.showMessageDialog(contentPane,
								"Ocurrio el siguiente error: \n"
										+ ex.getMessage(), "Error",
								JOptionPane.ERROR_MESSAGE);
						log
								.log(
										"Se produjo un error al intentar renovar el certificado para HTTPS del interfaz web.",
										2);
					}
				}
			} else {
				// TODO
			}
		} catch (CAManagerException ex) {
			JOptionPane.showMessageDialog(contentPane,
					"Ocurrio el siguiente error: \n" + ex.getMessage(),
					"Error", JOptionPane.ERROR_MESSAGE);
			log
					.log(
							"Se produjo un error al intentar renovar el certificado para HTTPS del interfaz web.",
							2);
		} catch (JDOMException ex) {
			JOptionPane.showMessageDialog(contentPane,
					"Ocurrio el siguiente error: \n" + ex.getMessage(),
					"Error", JOptionPane.ERROR_MESSAGE);
			log
					.log(
							"Se produjo un error al intentar renovar el certificado para HTTPS del interfaz web.",
							2);
		}
	}
}

class consolaCAMarco_jarrancar_actionAdapter implements
		java.awt.event.ActionListener {
	consolaCAMarco adaptee;

	consolaCAMarco_jarrancar_actionAdapter(consolaCAMarco adaptee) {
		this.adaptee = adaptee;
	}

	public void actionPerformed(ActionEvent e) {
		adaptee.jarrancar_actionPerformed(e);
	}
}

class consolaCAMarco_jdetener_actionAdapter implements
		java.awt.event.ActionListener {
	consolaCAMarco adaptee;

	consolaCAMarco_jdetener_actionAdapter(consolaCAMarco adaptee) {
		this.adaptee = adaptee;
	}

	public void actionPerformed(ActionEvent e) {
		adaptee.jdetener_actionPerformed(e);
	}
}
