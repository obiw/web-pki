package com.upm.eui.tfc.scp.consola;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import com.upm.eui.tfc.scp.utiles.*;
import com.upm.eui.tfc.scp.manager.ConfigManager;
import com.upm.eui.tfc.scp.manager.RAManager;
import javax.swing.border.*;


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
 * Clase encargada de generar el GUI para la inicializacion de la Autoridad
 * Certificadora. Invocara el metodo de inicializacion , una vez validados todos
 * los campos, de la Autoridad de Registro
 * 
 * @version 1.0
 */

public class inicializarCAMarco extends JFrame {

	private static final long serialVersionUID = 1L;
	JPanel contentPane;
	JTextField jdirectorio = new JTextField();
	JLabel jLabel1 = new JLabel();
	JLabel jLabel2 = new JLabel();
	JTextField jdominio = new JTextField();
	JLabel jLabel3 = new JLabel();
	JTextField jadministrador = new JTextField();
	JTextField jpuerto = new JTextField();
	JLabel jLabel4 = new JLabel();
	JCheckBox jCheckBox1 = new JCheckBox();
	JLabel jLabel5 = new JLabel();
	JTextField jCN = new JTextField();
	JLabel jLabel6 = new JLabel();
	JLabel jLabel7 = new JLabel();
	JTextField jOU1 = new JTextField();
	JTextField jOU2 = new JTextField();
	JTextField jOU3 = new JTextField();
	JLabel jLabel10 = new JLabel();
	JTextField jO = new JTextField();
	JLabel jLabel11 = new JLabel();
	JTextField jS = new JTextField();
	JLabel jLabel12 = new JLabel();
	JTextField jC = new JTextField();
	JTextField jL = new JTextField();
	private JLabel jLabel31;
	private JPasswordField jsmtppass;
	private JLabel jLabel30;
	private JTextField jsmtpuser;
	private JCheckBox jtsl;
	JLabel jLabel13 = new JLabel();
	JTextField jvalidez = new JTextField();
	JTextField jE = new JTextField();
	JLabel jLabel14 = new JLabel();
	JLabel jLabel15 = new JLabel();
	JLabel jLabel8 = new JLabel();
	JLabel jLabel9 = new JLabel();
	JLabel jLabel16 = new JLabel();
	JLabel jLabel17 = new JLabel();
	JLabel jLabel18 = new JLabel();
	JComboBox jtipo = new JComboBox();
	JComboBox jalgoritmo = new JComboBox();
	JComboBox jlongitud = new JComboBox();
	JPasswordField jpassword11 = new JPasswordField();
	JLabel jLabel19 = new JLabel();
	JLabel jLabel110 = new JLabel();
	JPasswordField jpassword12 = new JPasswordField();
	JLabel jLabel111 = new JLabel();
	JPasswordField jpassword21 = new JPasswordField();
	JLabel jLabel112 = new JLabel();
	JPasswordField jpassword22 = new JPasswordField();
	JTextField jadministrador1 = new JTextField();
	JLabel jLabel20 = new JLabel();
	JTextField jadministrador2 = new JTextField();
	JLabel jLabel21 = new JLabel();
	JTextField jadministrador3 = new JTextField();
	JLabel jLabel22 = new JLabel();
	JTextField jadministrador4 = new JTextField();
	JLabel jLabel23 = new JLabel();
	JTextField jsmtpservidor = new JTextField();
	JLabel jLabel25 = new JLabel();
	JTextField jsmtppuerto = new JTextField();
	JLabel jLabel26 = new JLabel();
	JButton jinicializar = new JButton();
	JButton jcancelar = new JButton();
	JCheckBox jhttps = new JCheckBox();
	JLabel jLabel27 = new JLabel();
	JLabel jLabel28 = new JLabel();
	JLabel jLabel29 = new JLabel();
	JLabel jLabel210 = new JLabel();
	JLabel jLabel211 = new JLabel();
	JLabel jLabel212 = new JLabel();
	JLabel jLabel213 = new JLabel();
	JLabel jLabel214 = new JLabel();
	JLabel jLabel215 = new JLabel();
	JLabel jLabel216 = new JLabel();
	JLabel jLabel217 = new JLabel();
	JLabel jLabel218 = new JLabel();
	JLabel jLabel219 = new JLabel();
	JLabel jLabel2110 = new JLabel();
	JLabel jLabel2111 = new JLabel();
	JLabel jLabel2112 = new JLabel();
	JLabel jLabel2113 = new JLabel();
	JPanel jPanel1 = new JPanel();
	TitledBorder titledBorder1;
	TitledBorder titledBorder2;
	JLabel jLabel24 = new JLabel();
	TitledBorder titledBorder3;
	TitledBorder titledBorder4;
	JPanel jPanel2 = new JPanel();
	TitledBorder titledBorder5;
	JLabel jLabel220 = new JLabel();
	JPanel jPanel3 = new JPanel();
	TitledBorder titledBorder6;
	TitledBorder titledBorder7;

	public inicializarCAMarco() {
		enableEvents(AWTEvent.WINDOW_EVENT_MASK);
		try {
			jbInit();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@SuppressWarnings("deprecation")
	private void jbInit() throws Exception {
		contentPane = (JPanel) this.getContentPane();
		titledBorder1 = new TitledBorder("");
		titledBorder2 = new TitledBorder("");
		titledBorder3 = new TitledBorder("");
		titledBorder4 = new TitledBorder("");
		titledBorder5 = new TitledBorder("");
		titledBorder6 = new TitledBorder("");
		titledBorder7 = new TitledBorder("");
		jdirectorio.setFont(new java.awt.Font("Verdana", 0, 10));
		jdirectorio.setNextFocusableComponent(jdominio);

		jdirectorio.setText("");
		jdirectorio.setBounds(new Rectangle(187, 67, 144, 21));
		contentPane.setLayout(null);
		this.setSize(new Dimension(833, 572));
		this.setTitle("Inicializar la Autoridad Certificadora");
		this.setResizable(false);
		jLabel1.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel1.setText("Directorio de instalacion:");
		jLabel1.setBounds(new Rectangle(15, 66, 167, 20));
		jLabel2.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel2.setRequestFocusEnabled(true);
		jLabel2.setText("Dominio DNS:");
		jLabel2.setBounds(new Rectangle(86, 90, 100, 24));
		jdominio.setFont(new java.awt.Font("Verdana", 0, 10));
		jdominio.setNextFocusableComponent(jadministrador);
		jdominio.setText("");
		jdominio.setBounds(new Rectangle(188, 94, 143, 20));
		jLabel3.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel3.setText("Email del administrador:");
		jLabel3.setBounds(new Rectangle(19, 118, 163, 22));
		jadministrador.setFont(new java.awt.Font("Verdana", 0, 10));
		jadministrador.setNextFocusableComponent(jsmtpservidor);
		jadministrador.setText("");
		jadministrador.setBounds(new Rectangle(188, 119, 144, 21));
		jpuerto.setFont(new java.awt.Font("Verdana", 0, 10));
		jpuerto.setNextFocusableComponent(jhttps);
		jpuerto.setText("");
		jpuerto.setBounds(new Rectangle(188, 43, 61, 19));
		jLabel4.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel4.setText("Puerto HTTP/HTTPS:");
		jLabel4.setBounds(new Rectangle(42, 40, 137, 18));
		jhttps.setText("jCheckBox1");
		jhttps.setBounds(new Rectangle(264, 9, 21, 16));
		jLabel5.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel5.setText("HTTPS:");
		jLabel5.setBounds(new Rectangle(254, 45, 54, 15));
		jCN.setFont(new java.awt.Font("Verdana", 0, 10));
		jCN.setNextFocusableComponent(jOU1);
		jCN.setText("");
		jCN.setBounds(new Rectangle(190, 15, 144, 20));
		jLabel6.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel6.setText("Common Name (CN):");
		jLabel6.setBounds(new Rectangle(44, 16, 139, 21));
		jLabel7.setBounds(new Rectangle(19, 37, 164, 21));
		jLabel7.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel7.setVerifyInputWhenFocusTarget(true);
		jLabel7.setText("Organizational Unit (OU):");
		jOU1.setFont(new java.awt.Font("Verdana", 0, 10));
		jOU1.setNextFocusableComponent(jOU2);
		jOU1.setText("");
		jOU1.setBounds(new Rectangle(191, 38, 144, 20));
		jOU2.setFont(new java.awt.Font("Verdana", 0, 10));
		jOU2.setNextFocusableComponent(jOU3);
		jOU2.setText("");
		jOU2.setBounds(new Rectangle(191, 64, 144, 20));
		jOU3.setFont(new java.awt.Font("Verdana", 0, 10));
		jOU3.setNextFocusableComponent(jO);
		jOU3.setText("");
		jOU3.setBounds(new Rectangle(190, 90, 144, 20));
		jLabel10.setBounds(new Rectangle(70, 114, 119, 21));
		jLabel10.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel10.setRequestFocusEnabled(true);
		jLabel10.setText("Organization (O):");
		jO.setFont(new java.awt.Font("Verdana", 0, 10));
		jO.setNextFocusableComponent(jC);
		jO.setText("");
		jO.setBounds(new Rectangle(190, 114, 144, 20));
		jLabel11.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel11.setRequestFocusEnabled(true);
		jLabel11.setText("Locality (L):");
		jLabel11.setBounds(new Rectangle(101, 188, 85, 21));
		jS.setFont(new java.awt.Font("Verdana", 0, 10));
		jS.setNextFocusableComponent(jL);
		jS.setText("");
		jS.setBounds(new Rectangle(192, 164, 144, 20));
		jLabel12.setBounds(new Rectangle(102, 136, 87, 21));
		jLabel12.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel12.setText("Country (C):");
		jC.setFont(new java.awt.Font("Verdana", 0, 10));
		jC.setNextFocusableComponent(jS);
		jC.setText("");
		jC.setBounds(new Rectangle(191, 138, 144, 20));
		jL.setFont(new java.awt.Font("Verdana", 0, 10));
		jL.setNextFocusableComponent(jE);
		jL.setOpaque(true);
		jL.setText("");
		jL.setBounds(new Rectangle(193, 188, 144, 20));
		jLabel13.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel13.setText("State (S):");
		jLabel13.setBounds(new Rectangle(116, 163, 71, 21));
		jvalidez.setFont(new java.awt.Font("Verdana", 0, 10));
		jvalidez.setNextFocusableComponent(jtipo);
		jvalidez.setText("");
		jvalidez.setBounds(new Rectangle(192, 235, 144, 20));
		jE.setFont(new java.awt.Font("Verdana", 0, 10));
		jE.setNextFocusableComponent(jvalidez);
		jE.setText("");
		jE.setBounds(new Rectangle(191, 212, 144, 20));
		jLabel14.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel14.setText("Email (E):");
		jLabel14.setBounds(new Rectangle(111, 213, 69, 21));
		jLabel15.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel15.setText("Validez (dias):");
		jLabel15.setBounds(new Rectangle(86, 234, 101, 21));
		jLabel8.setText("Organizational Unit (OU):");
		jLabel8.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel8.setVerifyInputWhenFocusTarget(true);
		jLabel8.setBounds(new Rectangle(18, 86, 166, 21));
		jLabel9.setText("Organizational Unit (OU):");
		jLabel9.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel9.setVerifyInputWhenFocusTarget(true);
		jLabel9.setBounds(new Rectangle(21, 63, 163, 21));
		jLabel16.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel16.setText("Tipo:");
		jLabel16.setBounds(new Rectangle(486, 13, 33, 20));
		jLabel17.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel17.setText("Algoritmo de firma:");
		jLabel17.setBounds(new Rectangle(391, 43, 134, 18));
		jLabel18.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel18.setText("Longitud:");
		jLabel18.setBounds(new Rectangle(454, 78, 67, 14));
		jtipo.setFont(new java.awt.Font("Verdana", 0, 10));
		jtipo.setNextFocusableComponent(jalgoritmo);
		jtipo.setToolTipText("");
		jtipo.setBounds(new Rectangle(537, 14, 110, 19));
		jalgoritmo.setFont(new java.awt.Font("Verdana", 0, 10));
		jalgoritmo.setNextFocusableComponent(jlongitud);
		jalgoritmo.setBounds(new Rectangle(535, 44, 111, 20));
		jlongitud.setFont(new java.awt.Font("Verdana", 0, 10));
		jlongitud.setNextFocusableComponent(jpassword11);
		jlongitud.setBounds(new Rectangle(536, 77, 112, 19));
		jpassword11.setFont(new java.awt.Font("Verdana", 0, 10));
		jpassword11.setNextFocusableComponent(jpassword12);
		jpassword11.setText("");
		jpassword11.setBounds(new Rectangle(570, 140, 133, 19));
		jLabel19.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel19.setText("Primera Contraseña:");
		jLabel19.setBounds(new Rectangle(422, 137, 137, 19));
		jLabel110.setBounds(new Rectangle(377, 163, 187, 19));
		jLabel110.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel110.setText("Repita Primera Contraseña:");
		jpassword12.setFont(new java.awt.Font("Verdana", 0, 10));
		jpassword12.setNextFocusableComponent(jpassword21);
		jpassword12.setBounds(new Rectangle(570, 164, 133, 19));
		jLabel111.setBounds(new Rectangle(415, 190, 142, 19));
		jLabel111.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel111.setText("Segunda Contraseña:");
		jpassword21.setFont(new java.awt.Font("Verdana", 0, 10));
		jpassword21.setNextFocusableComponent(jpassword22);
		jpassword21.setText("");
		jpassword21.setBounds(new Rectangle(570, 190, 133, 19));
		jLabel112.setBounds(new Rectangle(370, 213, 186, 19));
		jLabel112.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel112.setText("Repita Segunda Contraseña:");
		jpassword22.setFont(new java.awt.Font("Verdana", 0, 10));
		jpassword22.setNextFocusableComponent(jinicializar);
		jpassword22.setText("");
		jpassword22.setBounds(new Rectangle(569, 214, 133, 19));
		jadministrador1.setBounds(new Rectangle(147, 101, 140, 23));
		jadministrador1.setText("");
		jadministrador2.setBounds(new Rectangle(147, 101, 140, 23));
		jadministrador2.setText("");
		jsmtpservidor.setFont(new java.awt.Font("Verdana", 0, 10));
		jsmtpservidor.setNextFocusableComponent(jsmtppuerto);
		jsmtpservidor.setBounds(494, 15, 170, 22);
		jLabel25.setBounds(new Rectangle(405, 73, 89, 18));
		jLabel25.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel25.setText("Puerto SMTP:");
		jsmtppuerto.setBounds(new Rectangle(500, 73, 61, 21));
		jsmtppuerto.setFont(new java.awt.Font("Verdana", 0, 10));
		jsmtppuerto.setText("25");
		jLabel26.setFont(new java.awt.Font("Verdana", 1, 11));
		jLabel26.setText("Servidor SMTP:");
		jLabel26.setBounds(new Rectangle(394, 49, 107, 16));
		jtipo.addItem("RSA");
		jtipo.addItem("DSA");
		jlongitud.addItem("2048");
		jlongitud.addItem("1024");
		jlongitud.addItem("512");
		jalgoritmo.addItem(SignatureType.RSA_MD5);
		jalgoritmo.addItem(SignatureType.RSA_MD2);
		jalgoritmo.addItem(SignatureType.DSA_SHA1);
		jalgoritmo.addItem(SignatureType.RSA_SHA1);
		jinicializar.setBounds(new Rectangle(454, 9, 138, 25));
		jinicializar.setNextFocusableComponent(jcancelar);
		jinicializar.setText("Inicializar");
		jinicializar
				.addActionListener(new inicializarCAMarco_jinicializar_actionAdapter(
						this));
		jcancelar.setBounds(new Rectangle(598, 10, 141, 24));
		jcancelar.setText("Cancelar");
		jcancelar
				.addActionListener(new inicializarCAMarco_jcancelar_actionAdapter(
						this));
		jhttps.setFont(new java.awt.Font("Verdana", 0, 10));
		jhttps.setNextFocusableComponent(jdirectorio);
		jhttps.setText("jCheckBox2");
		jhttps.setBounds(new Rectangle(306, 45, 17, 16));
		jLabel27.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel27.setForeground(Color.red);
		jLabel27.setText("*");
		jLabel27.setBounds(new Rectangle(338, 47, 12, 14));
		jLabel28.setBounds(new Rectangle(337, 74, 12, 14));
		jLabel28.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel28.setForeground(Color.red);
		jLabel28.setText("*");
		jLabel29.setBounds(new Rectangle(338, 98, 12, 14));
		jLabel29.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel29.setForeground(Color.red);
		jLabel29.setText("*");
		jLabel210.setBounds(new Rectangle(337, 124, 12, 14));
		jLabel210.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel210.setForeground(Color.red);
		jLabel210.setText("*");
		jLabel211.setBounds(674, 18, 137, 22);
		jLabel211.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel211.setForeground(Color.red);
		jLabel211.setText("*");
		jLabel212.setBounds(new Rectangle(-42, 0, 42, 65));
		jLabel212.setText("*");
		jLabel213.setBounds(new Rectangle(568, 77, 12, 14));
		jLabel213.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel213.setForeground(Color.red);
		jLabel213.setText("*");
		jLabel214.setBounds(new Rectangle(339, 42, 12, 14));
		jLabel214.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel214.setForeground(Color.red);
		jLabel214.setText("*");
		jLabel215.setBounds(new Rectangle(338, 119, 12, 14));
		jLabel215.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel215.setForeground(Color.red);
		jLabel215.setText("*");
		jLabel216.setBounds(new Rectangle(341, 239, 12, 14));
		jLabel216.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel216.setForeground(Color.red);
		jLabel216.setText("*");
		jLabel217.setBounds(new Rectangle(654, 18, 12, 14));
		jLabel217.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel217.setForeground(Color.red);
		jLabel217.setText("*");
		jLabel218.setBounds(new Rectangle(653, 46, 12, 14));
		jLabel218.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel218.setForeground(Color.red);
		jLabel218.setText("*");
		jLabel219.setBounds(new Rectangle(652, 79, 12, 14));
		jLabel219.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel219.setForeground(Color.red);
		jLabel219.setText("*");
		jLabel2110.setBounds(new Rectangle(709, 145, 12, 14));
		jLabel2110.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel2110.setForeground(Color.red);
		jLabel2110.setText("*");
		jLabel2111.setBounds(new Rectangle(708, 167, 12, 14));
		jLabel2111.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel2111.setForeground(Color.red);
		jLabel2111.setText("*");
		jLabel2112.setBounds(new Rectangle(709, 193, 12, 14));
		jLabel2112.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel2112.setForeground(Color.red);
		jLabel2112.setText("*");
		jLabel2113.setBounds(new Rectangle(708, 219, 12, 14));
		jLabel2113.setFont(new java.awt.Font("Verdana", 1, 12));
		jLabel2113.setForeground(Color.red);
		jLabel2113.setText("*");
		jPanel1.setForeground(Color.black);
		jPanel1.setBorder(titledBorder4);
		jPanel1.setDebugGraphicsOptions(0);
		jPanel1.setDoubleBuffered(true);
		jPanel1.setOpaque(false);
		jPanel1.setBounds(new Rectangle(7, 30, 803, 122));
		jPanel1.setLayout(null);
		jLabel24.setFont(new java.awt.Font("Verdana", 1, 14));
		jLabel24.setForeground(SystemColor.desktop);
		jLabel24.setText("Configuracion de la Autoridad Certificadora");
		jLabel24.setBounds(new Rectangle(7, 155, 376, 17));
		jPanel2.setBorder(titledBorder5);
		jPanel2.setOpaque(false);
		jPanel2.setBounds(new Rectangle(5, 179, 805, 300));
		jPanel2.setLayout(null);
		jLabel220.setBounds(new Rectangle(7, 4, 288, 17));
		jLabel220.setText("Configuracion del servidor");
		jLabel220.setForeground(SystemColor.desktop);
		jLabel220.setFont(new java.awt.Font("Verdana", 1, 14));
		jPanel3.setBorder(titledBorder7);
		jPanel3.setOpaque(false);
		jPanel3.setBounds(new Rectangle(5, 493, 806, 44));
		jPanel3.setLayout(null);
		contentPane.add(jLabel212, null);
		contentPane.add(jPanel1, null);
		{
			jtsl = new JCheckBox();
			jPanel1.add(jtsl);
			jtsl.setText("TSL/SSL");
			jtsl.setBounds(583, 43, 81, 19);
			jtsl.setFont(new java.awt.Font("Verdana", 1, 11));
		}
		{
			jsmtpuser = new JTextField();
			jtsl.setNextFocusableComponent(jsmtpuser);
			jPanel1.add(jsmtpuser);
			jsmtpuser.setBounds(494, 69, 170, 22);
			jsmtpuser.setFont(new java.awt.Font("Verdana", 0, 10));
		}
		{
			jLabel30 = new JLabel();
			jPanel1.add(jLabel30);
			jLabel30.setText("Usuario SMTP:");
			jLabel30.setFont(new java.awt.Font("Verdana", 1, 11));
			jLabel30.setBounds(391, 70, 97, 20);
		}
		{
			jsmtppass = new JPasswordField();
			jPanel1.add(jsmtppass);
			jsmtppass.setBounds(527, 97, 137, 22);
			jsmtppass.setFont(new java.awt.Font("Verdana", 0, 10));
			jsmtppass.setNextFocusableComponent(jCN);
		}
		{
			jLabel31 = new JLabel();
			jPanel1.add(jLabel31);
			jLabel31.setText("Contraseña SMTP:");
			jLabel31.setFont(new java.awt.Font("Verdana", 1, 11));
			jLabel31.setBounds(368, 98, 153, 20);
			jPanel1.add(jLabel211);
			jPanel1.add(jsmtpservidor);
		}
		contentPane.add(jpuerto, null);
		contentPane.add(jLabel4, null);
		contentPane.add(jLabel1, null);
		contentPane.add(jLabel3, null);
		contentPane.add(jdirectorio, null);
		contentPane.add(jdominio, null);
		contentPane.add(jadministrador, null);
		contentPane.add(jLabel2, null);
		contentPane.add(jhttps, null);
		contentPane.add(jLabel5, null);
		contentPane.add(jLabel27, null);
		contentPane.add(jLabel28, null);
		contentPane.add(jLabel29, null);
		contentPane.add(jLabel210, null);
		contentPane.add(jLabel25, null);
		contentPane.add(jLabel26, null);
		contentPane.add(jsmtppuerto, null);
		jsmtppuerto.setNextFocusableComponent(jtsl);
		jsmtppuerto.addFocusListener(new FocusAdapter() {
			public void focusGained(FocusEvent evt) {
				jsmtppuertoFocusGained(evt);
			}
		});
		contentPane.add(jLabel213, null);
		jPanel2.add(jCN, null);
		jPanel2.add(jLabel6, null);
		jPanel2.add(jLabel7, null);
		jPanel2.add(jOU1, null);
		jPanel2.add(jLabel9, null);
		jPanel2.add(jOU2, null);
		jPanel2.add(jLabel8, null);
		jPanel2.add(jOU3, null);
		jPanel2.add(jLabel214, null);
		jPanel2.add(jO, null);
		jPanel2.add(jC, null);
		jPanel2.add(jLabel215, null);
		jPanel2.add(jLabel10, null);
		jPanel2.add(jLabel12, null);
		jPanel2.add(jtipo, null);
		jPanel2.add(jLabel16, null);
		jPanel2.add(jLabel17, null);
		jPanel2.add(jalgoritmo, null);
		jPanel2.add(jLabel18, null);
		jPanel2.add(jlongitud, null);
		jPanel2.add(jLabel217, null);
		jPanel2.add(jLabel218, null);
		jPanel2.add(jLabel219, null);
		jPanel2.add(jS, null);
		jPanel2.add(jLabel13, null);
		jPanel2.add(jLabel11, null);
		jPanel2.add(jL, null);
		jPanel2.add(jLabel14, null);
		jPanel2.add(jE, null);
		jPanel2.add(jLabel15, null);
		jPanel2.add(jvalidez, null);
		jPanel2.add(jLabel216, null);
		jPanel2.add(jpassword11, null);
		jPanel2.add(jLabel19, null);
		jPanel2.add(jLabel2110, null);
		jPanel2.add(jLabel2111, null);
		jPanel2.add(jLabel2112, null);
		jPanel2.add(jLabel2113, null);
		jPanel2.add(jpassword22, null);
		jPanel2.add(jpassword21, null);
		jPanel2.add(jpassword12, null);
		jPanel2.add(jLabel110, null);
		jPanel2.add(jLabel111, null);
		jPanel2.add(jLabel112, null);
		contentPane.add(jPanel3, null);
		jPanel3.add(jcancelar, null);
		jPanel3.add(jinicializar, null);
		contentPane.add(jLabel220, null);
		contentPane.add(jLabel24, null);
		contentPane.add(jPanel2, null);
		contentPane.add(jhttps, null);
		JOptionPane
				.showMessageDialog(
						contentPane,
						"Es la primera vez que inicia la aplicacion y la Autoridad Certificadora no esta inicializada."
								+ "\nUna vez inicializada la CA cuando arranque la aplicacion accedera directamente a la consola de administracion.",
						"Informacion", JOptionPane.INFORMATION_MESSAGE);

	}

	// Modificado para poder salir cuando se cierra la ventana
	protected void processWindowEvent(WindowEvent e) {
		super.processWindowEvent(e);
		if (e.getID() == WindowEvent.WINDOW_CLOSING) {
			System.exit(0);
		}
	}

	void jcancelar_actionPerformed(ActionEvent e) {
		JOptionPane
				.showMessageDialog(
						contentPane,
						"La CA no fue inicializada. Podra hacerlo ejecutando de nuevo la aplicacion.",
						"Cancelar la inicializacion de la CA",
						JOptionPane.INFORMATION_MESSAGE);
		System.exit(0);
	}

	void jinicializar_actionPerformed(ActionEvent e) {
		if (comprobarCampos()) {
			if (JOptionPane
					.showConfirmDialog(
							contentPane,
							"Una vez inicializada la CA no podra modificar los campos que aqui aparecen."
									+ "\n¿Esta seguro de que desea inicializar la CA con estos parametros?",
							"Inicializar la CA", JOptionPane.YES_NO_OPTION) == 0) {
				if (inicializarCA()) {
					if (JOptionPane
							.showConfirmDialog(
									contentPane,
									"La CA se inicializo con exito. ¿Desea arrancar la Consola de Administracion ahora?",
									"Arrancar la consola",
									JOptionPane.YES_NO_OPTION) == 0) {
						consolaCA.inicializar();
						this.dispose();
					} else {
						JOptionPane
								.showMessageDialog(
										contentPane,
										"Podra acceder a la Consola de Administracion volviendo a ejecutar la aplicacion.",
										"Salir",
										JOptionPane.INFORMATION_MESSAGE);
						System.exit(0);
					}
				}
			}
		} else {
			JOptionPane
					.showMessageDialog(
							contentPane,
							"Falta algun campo o han sido incorrectamente introducidos."
									+ "\nRecuerde que los campos referentes a puertos y el de la validez de la CA deben ser valores numericos.",
							"Error", JOptionPane.ERROR_MESSAGE);

		}
	}

	/**
	 * inicializarCA
	 * 
	 * @return boolean
	 */
	private boolean inicializarCA() {
		RAManager ra = new RAManager();

		try {
			ConfigManager.guardarParametro("INSTALACION/DIRECTORIO",
					jdirectorio.getText());
			ConfigManager.guardarParametro(
					"RA/AUTORIZACION/FICHEROS/FICHEROCP", jdirectorio.getText()
							+ "/data/usuarios_cp.txt");
			ConfigManager.guardarParametro(
					"RA/AUTORIZACION/FICHEROS/FICHEROSSL", jdirectorio
							.getText()
							+ "/data/usuarios_ssl.txt");
			ConfigManager.guardarParametro("RA/REGISTRO/FICHEROS/FICHEROCP",
					jdirectorio.getText() + "/data/registro_cp.xml");
			ConfigManager.guardarParametro("RA/REGISTRO/FICHEROS/FICHEROSSL",
					jdirectorio.getText() + "/data/registro_ssl.xml");

			ConfigManager.guardarParametro("SMTP/PLANTILLAS/CP/TEXT",
					jdirectorio.getText() + "/conf/plantilla_correo_cp.txt");
			ConfigManager.guardarParametro("SMTP/PLANTILLAS/CP/HTML",
					jdirectorio.getText() + "/conf/plantilla_correo_cp.htm");
			ConfigManager.guardarParametro("SMTP/PLANTILLAS/SSL/TEXT",
					jdirectorio.getText() + "/conf/plantilla_correo_ssl.txt");
			ConfigManager.guardarParametro("SMTP/PLANTILLAS/SSL/HTML",
					jdirectorio.getText() + "/conf/plantilla_correo_ssl.htm");

			if (jhttps.isSelected()) {
				ConfigManager.guardarParametro("SERVIDOR/SSL/ACTIVADO", "S");
				ConfigManager.guardarParametro("SERVIDOR/SSL/PUERTO", jpuerto
						.getText());
				ConfigManager
						.guardarParametro("CA/DOMINIO", jdominio.getText());
				if (Integer.parseInt(jpuerto.getText()) == 443) {
					ConfigManager.guardarParametro("CA/URLACTIVA", "https://"
							+ jdominio.getText());
				} else {
					ConfigManager.guardarParametro("CA/URLACTIVA", "https://"
							+ jdominio.getText() + ":" + jpuerto.getText());
				}
			} else {
				ConfigManager.guardarParametro("SERVIDOR/PUERTO", jpuerto
						.getText());
				ConfigManager
						.guardarParametro("CA/DOMINIO", jdominio.getText());
				if (Integer.parseInt(jpuerto.getText()) == 80) {
					ConfigManager.guardarParametro("CA/URLACTIVA", "http://"
							+ jdominio.getText());
				} else {
					ConfigManager.guardarParametro("CA/URLACTIVA", "http://"
							+ jdominio.getText() + ":" + jpuerto.getText());
				}

			}
			ConfigManager.guardarParametro("SERVIDOR/ADMINISTRADOR",
					jadministrador.getText());

			ConfigManager.guardarParametro("SMTP/SERVIDOR", jsmtpservidor
					.getText());
			ConfigManager
					.guardarParametro("SMTP/PUERTO", jsmtppuerto.getText());
			if (jtsl.isSelected()) {
				ConfigManager.guardarParametro("SMTP/TSL", "S");
			} else {
				ConfigManager.guardarParametro("SMTP/TSL", "N");
			}
			ConfigManager.guardarParametro("SMTP/USER", jsmtpuser.getText());
			ConfigManager
					.guardarParametro("SMTP/PASSWORD", jsmtppass.getText());
			if (ra.inicializar(jpassword11.getPassword(), jpassword21
					.getPassword(), jCN.getText(), jOU1.getText(), jOU2
					.getText(), jOU3.getText(), jO.getText(), jC.getText(), jL
					.getText(), jS.getText(), jE.getText(), Integer
					.parseInt(jvalidez.getText()), jtipo.getSelectedItem()
					.toString(), Integer.parseInt(jlongitud.getSelectedItem()
					.toString()), jalgoritmo.getSelectedItem().toString())) {
				ConfigManager.guardarParametro("CA/INICIALIZADA", "S");
				return true;
			} else {
				JOptionPane.showMessageDialog(contentPane,
						"Ocurrio el siguiente error: \n" + ra.getLastError(),
						"Error", JOptionPane.ERROR_MESSAGE);

				return false;
			}

		} catch (Exception ex) {
			JOptionPane.showMessageDialog(contentPane,
					"Ocurrio el siguiente error: \n" + ex.getMessage(),
					"Error", JOptionPane.ERROR_MESSAGE);
			return false;
		}
	}

	/**
	 * comprobarCampos
	 * 
	 * @return boolean
	 */
	private boolean comprobarCampos() {
		boolean ok = true;

		ok &= (jpuerto.getText().compareTo("") != 0);
		ok &= (jsmtpservidor.getText().compareTo("") != 0);
		ok &= (jsmtppuerto.getText().compareTo("") != 0);
		ok &= (jdominio.getText().compareTo("") != 0);
		ok &= (jdirectorio.getText().compareTo("") != 0);
		ok &= (jadministrador.getText().compareTo("") != 0);
		ok &= (jOU1.getText().compareTo("") != 0);
		ok &= (jO.getText().compareTo("") != 0);
		ok &= (jvalidez.getText().compareTo("") != 0);
		ok &= ((new String(jpassword11.getPassword())).compareTo("") != 0);
		ok &= ((new String(jpassword12.getPassword())).compareTo("") != 0);
		ok &= ((new String(jpassword21.getPassword())).compareTo("") != 0);
		ok &= ((new String(jpassword22.getPassword())).compareTo("") != 0);
		ok &= ((new String(jpassword11.getPassword())).compareTo(new String(jpassword12.getPassword())) == 0);
		ok &= ((new String(jpassword21.getPassword())).compareTo(new String(jpassword22.getPassword())) == 0);
		ok &= numerico(jpuerto.getText());
		ok &= numerico(jsmtppuerto.getText());
		ok &= numerico(jvalidez.getText());
		
		return ok;
	}

	private boolean numerico(String valor) {
		for (int i = 0; i < valor.length(); i++) {
			char caracter = valor.charAt(i);
			if (caracter < '0' || caracter > '9') {
				return false;
			}
		}
		return true;
	}
	
	private void jsmtppuertoFocusGained(FocusEvent evt) {
		jsmtppuerto.selectAll();
	}

}

class inicializarCAMarco_jcancelar_actionAdapter implements
		java.awt.event.ActionListener {
	inicializarCAMarco adaptee;

	inicializarCAMarco_jcancelar_actionAdapter(inicializarCAMarco adaptee) {
		this.adaptee = adaptee;
	}

	public void actionPerformed(ActionEvent e) {
		adaptee.jcancelar_actionPerformed(e);
	}
}

class inicializarCAMarco_jinicializar_actionAdapter implements
		java.awt.event.ActionListener {
	inicializarCAMarco adaptee;

	inicializarCAMarco_jinicializar_actionAdapter(inicializarCAMarco adaptee) {
		this.adaptee = adaptee;
	}

	public void actionPerformed(ActionEvent e) {
		adaptee.jinicializar_actionPerformed(e);
	}

}
