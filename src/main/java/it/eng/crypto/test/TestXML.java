package it.eng.crypto.test;

import java.io.FileInputStream;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;

import org.jcp.xml.dsig.internal.dom.DOMX509Data;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class TestXML {

    /**
     * @param args
     */
    public static void main(String[] args) throws Exception {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        // Document doc = dbf.newDocumentBuilder().parse(new
        // FileInputStream("C:/Michele/Regione_Toscana/SmartCard/XML_Signature/XMLSignatureSample.xml"));
        Document doc = dbf.newDocumentBuilder().parse(new FileInputStream("C:/Michele/aurigaweb.xml.xml"));
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        }
        String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",
                (Provider) Class.forName(providerName).newInstance());
        DOMStructure struct = new DOMStructure(nl.item(0));
        XMLSignature signature = fac.unmarshalXMLSignature(struct);

        List lst = signature.getKeyInfo().getContent();

        for (int i = 0; i < lst.size(); i++) {
            Object obj = lst.get(i);
            if (obj instanceof DOMX509Data) {
                // Controllo del certificato
                X509Certificate certificate = (X509Certificate) ((DOMX509Data) obj).getContent().get(0);
                System.out.println(certificate.getIssuerX500Principal().getName());
                System.out.println(certificate.getSubjectX500Principal().getName());
                System.out.println(certificate.getPublicKey());
                DOMValidateContext context = new DOMValidateContext(certificate.getPublicKey(), nl.item(0));

                boolean bol = signature.validate(context);
                System.out.println(bol);

            }
        }

    }
}