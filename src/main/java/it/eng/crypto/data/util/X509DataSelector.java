package it.eng.crypto.data.util;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;

import org.jcp.xml.dsig.internal.dom.DOMX509Data;

public class X509DataSelector extends KeySelector {

    public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method,
            XMLCryptoContext context) throws KeySelectorException {

        if (keyInfo == null) {
            throw new KeySelectorException("Null KeyInfo object!");
        }
        SignatureMethod sm = (SignatureMethod) method;
        List list = keyInfo.getContent();

        for (int i = 0; i < list.size(); i++) {
            XMLStructure xmlStructure = (XMLStructure) list.get(i);

            if (xmlStructure instanceof DOMX509Data) {
                X509Certificate certificate = null;
                try {
                    List lista = ((DOMX509Data) xmlStructure).getContent();
                    System.out.println(lista.get(0));

                } catch (Exception ke) {
                    throw new KeySelectorException(ke);
                }

            }
        }
        throw new KeySelectorException("No KeyValue element found!");
    }

    static boolean algEquals(String algURI, String algName) {
        if (algName.equalsIgnoreCase("DSA") && algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) {
            return true;
        } else if (algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
            return true;
        } else {
            return false;
        }
    }
}
