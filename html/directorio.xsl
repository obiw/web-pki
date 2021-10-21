<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="html"/>

<xsl:template match="/">

<HTML>

<link rel="stylesheet" type="text/css" href="Estilo/estilo.css"></link>
<script language="JavaScript" src="funciones.js"></script>
<body>
  <p align="left"><a href="/">Inicio</a> &gt; <font size="1">Directorio publico de 
  certificados</font></p>
        <p align="right">
        <a href="Imagenes/buscar.jpg"><img border="0" src="Imagenes/buscar.jpg" width="24" height="23"></img></a><a href="javascript:abrirVentana('buscar_detalle.htm',675,260)"><font size="1">Buscar un certificado</font></a></p>
        <hr></hr>
<center>
<table border="0" cellpadding="0" cellspacing="0" style="border-collapse: collapse" width="988" height="65">
  <tr>
    <td width="14" background="Imagenes/esquina_superior_izquierda.jpg" height="19"></td>
    <td background="Imagenes/superior.jpg" width="947" height="19">
          <table border="0" cellpadding="0" style="border-collapse: collapse" bordercolor="#111111" width="100%" cellspacing="0">
          <tr>
            <td width="20%" background="Imagenes/superior.jpg" align="center">
            <b><font size="1">Nombre y apellidos</font></b></td>
            <td width="20%" background="Imagenes/superior.jpg" align="center">
            <b><font size="1">Correo electronico</font></b></td>
            <td width="20%" background="Imagenes/superior.jpg" align="center">
            <b><font size="1">Valido desde</font></b></td>
            <td width="20%" background="Imagenes/superior.jpg" align="center">
            <b><font size="1">Valido hasta</font></b></td>
            <td width="20%" background="Imagenes/superior.jpg" align="center"> </td>
          </tr>
        </table>
        </td>
    <td width="15" background="Imagenes/esquina_superior_derecha.jpg"> </td>
  </tr>
  <tr>
    <td width="14" background="Imagenes/izquierda.jpg" height="19"> </td>
    <td width="947" background="Imagenes/centro.jpg" height="27">
          <table border="0" cellpadding="0" style="border-collapse: collapse" bordercolor="#111111" width="100%" cellspacing="0" align="left">
          <xsl:for-each select="CERTIFICADOS/CERTIFICADO[TIPO='CP']">
          <tr>
            		<td width="20%" align="center"><font size="1"><xsl:value-of select="CN" /></font></td>
              		<td width="20%" align="center"><font size="1">
            		<a><xsl:attribute name="href">mailto:<xsl:value-of select="EMAIL" /></xsl:attribute><xsl:value-of select="EMAIL" /></a></font></td>
            		<td width="20%" align="center"><font size="1"><p align="left"><xsl:value-of select="DESDE" /></p></font></td>
            		<td width="20%" align="center"><font size="1"><xsl:value-of select="HASTA" /></font></td>
            		<td width="20%" align="center">
            		<a><xsl:attribute name="href">
                    javascript:abrirVentana('serverCA.htm?operacion=detalle&amp;tipo=cp&amp;cert=<xsl:value-of select="FICHERO" />',675,225)</xsl:attribute><img border="0" src="Imagenes/Enriquez.gif" width="16" height="16"></img></a></td>
                    </tr>
          </xsl:for-each>
        </table>
    </td>
    <td width="15" background="Imagenes/derecha.jpg"> </td>
  </tr>
  <tr>
    <td width="14" background="Imagenes/esquina_inferior_izquierda.jpg" height="19"> </td>
    <td width="588" background="Imagenes/inferior.jpg" height="19"> </td>
    <td width="15" background="Imagenes/esquina_inferior_derecha.jpg"> </td>
  </tr>
</table>
</center>
<p> </p>
        <p align="right">
         </p>
        <hr></hr>
<center>
<table border="0" cellpadding="0" cellspacing="0" style="border-collapse: collapse" width="988" height="65">
  <tr>
    <td width="14" background="Imagenes/esquina_superior_izquierda.jpg" height="19"> </td>
    <td background="Imagenes/superior.jpg" width="947" height="19">
          <table border="0" cellpadding="0" style="border-collapse: collapse" bordercolor="#111111" width="100%">
          <tr>
            <td width="20%" align="center"><b><font size="1">Nombre del sitio seguro</font></b></td>
            <td width="20%" align="center"><b><font size="1">Valido desde</font></b></td>
            <td width="20%" align="center"><b><font size="1">Valido hasta</font></b></td>
            <td width="20%" align="center"> </td>
          </tr>
       
        </table>
        </td>
    <td width="15" background="Imagenes/esquina_superior_derecha.jpg"> </td>
  </tr>
  <tr>
    <td width="14" background="Imagenes/izquierda.jpg" height="19"> </td>
    <td width="947" background="Imagenes/centro.jpg" height="27">
          <table border="0" cellpadding="0" style="border-collapse: collapse" bordercolor="#111111" width="100%" height="16">
          <xsl:for-each select="CERTIFICADOS/CERTIFICADO[TIPO='SSL']">
          <tr>
            		<td width="20%" align="center" height="1"><font size="1"><xsl:value-of select="CN" /></font></td>
              	  	<td width="20%" align="center" height="1"><font size="1"><xsl:value-of select="DESDE" /></font></td>
            		<td width="20%" align="center" height="1"><font size="1"><xsl:value-of select="HASTA" /></font></td>
            		<td width="20%" align="center" height="1">
            		<a><xsl:attribute name="href">javascript:abrirVentana('serverCA.htm?operacion=detalle&amp;tipo=ssl&amp;cert=<xsl:value-of select="FICHERO" />',675,225)</xsl:attribute><img border="0" src="Imagenes/certcert_small.gif" width="16" height="16"></img></a></td>
          </tr>
          </xsl:for-each>
        </table>
    </td>
    <td width="15" background="Imagenes/derecha.jpg"> </td>
  </tr>
  <tr>
    <td width="14" background="Imagenes/esquina_inferior_izquierda.jpg" height="19"> </td>
    <td width="588" background="Imagenes/inferior.jpg" height="19"> </td>
    <td width="15" background="Imagenes/esquina_inferior_derecha.jpg"> </td>
  </tr>
</table>      
</center>
</body>
</HTML>

</xsl:template>
</xsl:stylesheet>