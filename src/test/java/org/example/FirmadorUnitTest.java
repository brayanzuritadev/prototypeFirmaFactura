package org.example;

import junit.framework.TestCase;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.Test;

import javax.xml.parsers.ParserConfigurationException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FirmadorUnitTest extends TestCase {


    @Test
    public void testFirmarXML() throws URISyntaxException, ParserConfigurationException, XMLSecurityException, org.xml.sax.SAXException {

        String xmlPath = "C:\\Users\\Brayan\\Downloads\\Certificado\\FacturaE.xml";

        String xmlPathFirmado = "C:\\Users\\Brayan\\Downloads\\Certificado\\FacturaF.xml";

        try {

            Firmador firmador = Firmador.getInstance();

            PrivateKey privateKey = firmador.getPrivateKey("C:/Users/Brayan/Downloads/Certificado/PrivateKey.pem");

            X509Certificate cert =  firmador.getX509Certificate("C:/Users/Brayan/Downloads/Certificado/Certificado.pem");

            byte[] xmlFirmado = firmador.firmarDsig(xmlPath, privateKey, xmlPathFirmado, cert);

            String respuesta = new String(xmlFirmado);

            System.out.println("facturaFirmada: " + respuesta);

        } catch (IOException | GeneralSecurityException ex) {

            Logger.getLogger(FirmadorUnitTest.class.getName()).log(Level.SEVERE, null, ex);

        }

    }


}