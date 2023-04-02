package org.example;

import java.io.*;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.codec.binary.Base64;
import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.XMLUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 *
 * @author
 */

public class Firmador {
    // http://stackoverflow.com/questions/7224626/how-to-sign-string-with-private-key
    private static Firmador instancia;
    private String ALG = "SHA1withRSA";

    static {
        Init.init();
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Obtener un firmador por defecto.
     *
     * @return un Firmador.
     */

    public static Firmador getInstance() {
        if (instancia == null) {
            instancia = new Firmador();
        }

        return instancia;

    }

    private Firmador() {
    }

    //// Todo: Colocar en un solo directorio la llave privada con la publica

    /**
     * Esta funcion añade una firma a un documento XML.
     *
     * @param datos Documento a firmar <i>XML</i>.
     * @param priv Clave privada.
     * @param cert Certificado del firmante.
     * @return Retorna el documento con una firma.
     * @throws ParserConfigurationException
     * @throws IOException
     * @throws SAXException
     * @throws XMLSecurityException
     */
    public static byte[] firmarDsig(String XMLpath, PrivateKey priv, String XMLFirmadoPath, X509Certificate... cert) throws ParserConfigurationException, IOException, SAXException, XMLSecurityException {
        ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "");
        Document documento = leerXML(XMLpath);

        Element root = (Element) documento.getFirstChild();
        documento.setXmlStandalone(false);

        XMLSignature signature = new XMLSignature(documento, documento.getDocumentURI(), XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        root.appendChild(signature.getElement());

        Transforms transforms = new Transforms(documento);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        signature.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);

        if (cert != null) {
            signature.addKeyInfo(cert[0]);
        }

        signature.sign(priv);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(documento, baos);


        generarDocumento(XMLFirmadoPath, baos.toString().getBytes());

        return baos.toString().getBytes();
    }

    public static void generarDocumento(String xmlFirmadoPath, byte[] xmlFirmado) throws IOException {

        File archivo = new File(xmlFirmadoPath);

        boolean creado = archivo.createNewFile();

        if(creado){
            FileWriter escritor = new FileWriter(archivo);
            String xmlFirmadoCadena = new String(xmlFirmado);
            escritor.write(xmlFirmadoCadena);
            escritor.close();
        }else{
            System.out.println("No se pudo crear el archivo");
        }
    }

    public static Document leerXML(String XMLpath) throws ParserConfigurationException, IOException, SAXException{

        byte[] documentoXML = Files.readAllBytes(Paths.get(XMLpath));

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder;

        factory.setNamespaceAware(true);
        builder = factory.newDocumentBuilder();

        return builder.parse(new ByteArrayInputStream(documentoXML));
    }

    public static RSAPrivateKey getPrivateKey(String filename) throws IOException, GeneralSecurityException, URISyntaxException {
        String privateKeyContent = new String(Files.readAllBytes(Paths.get(filename)));

        privateKeyContent = privateKeyContent.replaceAll("\\n", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "");
        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyContent));
        RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpecPKCS8);

        return privKey;
    }

    public static X509Certificate getX509Certificate(String filename) throws IOException, CertificateException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(filename);
        X509Certificate cer = (X509Certificate) fact.generateCertificate(is);

        return cer;
    }

}
