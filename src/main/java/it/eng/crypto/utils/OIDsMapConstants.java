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

/*
 * To change this template, choose Tools | Templates and open the template in the editor.
 */
package it.eng.crypto.utils;

import java.util.HashMap;

/**
 *
 * @author Quaranta_M
 */
public class OIDsMapConstants {

    private static final HashMap<String, String> digestNames = new HashMap<String, String>();
    private static final HashMap<String, String> algorithmNames = new HashMap<String, String>();

    static {
	digestNames.put("1.2.840.113549.2.5", "MD5");
	digestNames.put("1.2.840.113549.2.2", "MD2");
	digestNames.put("1.3.14.3.2.26", "SHA1");
	digestNames.put("2.16.840.1.101.3.4.2.4", "SHA224");
	digestNames.put("2.16.840.1.101.3.4.2.1", "SHA256");
	digestNames.put("2.16.840.1.101.3.4.2.2", "SHA384");
	digestNames.put("2.16.840.1.101.3.4.2.3", "SHA512");
	digestNames.put("1.3.36.3.2.2", "RIPEMD128");
	digestNames.put("1.3.36.3.2.1", "RIPEMD160");
	digestNames.put("1.3.36.3.2.3", "RIPEMD256");
	digestNames.put("1.2.840.113549.1.1.4", "MD5");
	digestNames.put("1.2.840.113549.1.1.2", "MD2");
	digestNames.put("1.2.840.113549.1.1.5", "SHA1");
	digestNames.put("1.2.840.113549.1.1.14", "SHA224");
	digestNames.put("1.2.840.113549.1.1.11", "SHA256");
	digestNames.put("1.2.840.113549.1.1.12", "SHA384");
	digestNames.put("1.2.840.113549.1.1.13", "SHA512");
	digestNames.put("1.2.840.113549.2.5", "MD5");
	digestNames.put("1.2.840.113549.2.2", "MD2");
	digestNames.put("1.2.840.10040.4.3", "SHA1");
	digestNames.put("2.16.840.1.101.3.4.3.1", "SHA224");
	digestNames.put("2.16.840.1.101.3.4.3.2", "SHA256");
	digestNames.put("2.16.840.1.101.3.4.3.3", "SHA384");
	digestNames.put("2.16.840.1.101.3.4.3.4", "SHA512");
	digestNames.put("1.3.36.3.3.1.3", "RIPEMD128");
	digestNames.put("1.3.36.3.3.1.2", "RIPEMD160");
	digestNames.put("1.3.36.3.3.1.4", "RIPEMD256");

	algorithmNames.put("1.2.840.113549.1.1.1", "RSA");
	algorithmNames.put("1.2.840.10040.4.1", "DSA");
	algorithmNames.put("1.2.840.113549.1.1.2", "RSA");
	algorithmNames.put("1.2.840.113549.1.1.4", "RSA");
	algorithmNames.put("1.2.840.113549.1.1.5", "RSA");
	algorithmNames.put("1.2.840.113549.1.1.14", "RSA");
	algorithmNames.put("1.2.840.113549.1.1.11", "RSA");
	algorithmNames.put("1.2.840.113549.1.1.12", "RSA");
	algorithmNames.put("1.2.840.113549.1.1.13", "RSA");
	algorithmNames.put("1.2.840.10040.4.3", "DSA");
	algorithmNames.put("2.16.840.1.101.3.4.3.1", "DSA");
	algorithmNames.put("2.16.840.1.101.3.4.3.2", "DSA");
	algorithmNames.put("1.3.36.3.3.1.3", "RSA");
	algorithmNames.put("1.3.36.3.3.1.2", "RSA");
	algorithmNames.put("1.3.36.3.3.1.4", "RSA");
    }

    public static HashMap<String, String> getAlgorithmNames() {
	return algorithmNames;
    }

    public static HashMap<String, String> getDigestNames() {
	return digestNames;
    }
}
