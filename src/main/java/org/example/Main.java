package org.example;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

// Press Shift twice to open the Search Everywhere dialog and type `show whitespaces`,
// then press Enter. You can now see whitespace characters in your code.
public class Main {
    public static void main(String[] args) {

        /*if(args.length < 4 || args.length > 4){
            System.out.println("Se espera 4 argumentos");
            return;
        }

        for (int i = 0; i < args.length; i++) {

            System.out.println("Argumento = " + args[i]);
        }*/




        try {

            Firmador firmador = Firmador.getInstance();

            String documentoXMLFirmado = "C:\\Users\\Brayan\\Downloads\\Certificado\\FacturaF.xml";

            String xmlPath = "C:\\Users\\Brayan\\Downloads\\Certificado\\FacturaE.xml";

            PrivateKey privateKey = firmador.getPrivateKey("C:/Users/Brayan/Downloads/Certificado/PrivateKey.pem");

            X509Certificate cert =  firmador.getX509Certificate("C:/Users/Brayan/Downloads/Certificado/Certificado.pem");

            byte[] xmlFirmado = firmador.firmarDsig(xmlPath, privateKey,documentoXMLFirmado, cert);

            String respuesta = new String(xmlFirmado);

            System.out.println("facturaFirmada: " + respuesta);

        } catch (IOException | GeneralSecurityException ex) {

            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);

        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (XMLSecurityException e) {
            throw new RuntimeException(e);
        } catch (SAXException e) {
            throw new RuntimeException(e);
        }
    }
}