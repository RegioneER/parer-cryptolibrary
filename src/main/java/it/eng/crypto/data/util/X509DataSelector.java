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

import javax.xml.crypto.dsig.keyinfo.X509Data;

public class X509DataSelector extends KeySelector {

    public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose,
            AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {

        if (keyInfo == null) {
            throw new KeySelectorException("Null KeyInfo object!");
        }
        SignatureMethod sm = (SignatureMethod) method;
        List list = keyInfo.getContent();

        for (int i = 0; i < list.size(); i++) {
            XMLStructure xmlStructure = (XMLStructure) list.get(i);

            if (xmlStructure instanceof X509Data) {
                try {
                    X509Data x509Data = (X509Data) xmlStructure;
                    List<?> x509Content = x509Data.getContent();
                    for (Object obj : x509Content) {
                        if (obj instanceof X509Certificate) {
                            X509Certificate certificate = (X509Certificate) obj;
                            System.out.println(certificate);
                            // You can return or use the certificate as needed
                        }
                    }
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
        } else if (algName.equalsIgnoreCase("RSA")
                && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
            return true;
        } else {
            return false;
        }
    }
}
