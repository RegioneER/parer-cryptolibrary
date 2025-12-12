/*
 * Engineering Ingegneria Informatica S.p.A.
 *
 * Copyright (C) 2023 Regione Emilia-Romagna <p/> This program is free software: you can
 * redistribute it and/or modify it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version. <p/> This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Affero General Public License for more details. <p/> You should
 * have received a copy of the GNU Affero General Public License along with this program. If not,
 * see <https://www.gnu.org/licenses/>.
 */

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

import javax.xml.crypto.dsig.keyinfo.X509Data;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class TestXML {

    /**
     * @param args
     */
    public static void main(String[] args) throws Exception {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder()
                .parse(new FileInputStream("C:/Michele/aurigaweb.xml.xml"));
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        }
        String providerName = System.getProperty("jsr105Provider",
                "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",
                (Provider) Class.forName(providerName).newInstance());
        DOMStructure struct = new DOMStructure(nl.item(0));
        XMLSignature signature = fac.unmarshalXMLSignature(struct);

        List<?> lst = signature.getKeyInfo().getContent();

        for (Object obj : lst) {
            if (obj instanceof X509Data) {
                X509Data x509Data = (X509Data) obj;
                List<?> x509Content = x509Data.getContent();
                for (Object content : x509Content) {
                    if (content instanceof X509Certificate) {
                        X509Certificate certificate = (X509Certificate) content;
                        System.out.println(certificate.getIssuerX500Principal().getName());
                        System.out.println(certificate.getSubjectX500Principal().getName());
                        System.out.println(certificate.getPublicKey());
                        DOMValidateContext context = new DOMValidateContext(
                                certificate.getPublicKey(), nl.item(0));
                        boolean bol = signature.validate(context);
                        System.out.println(bol);
                        break;
                    }
                }
            }
        }
    }

}
