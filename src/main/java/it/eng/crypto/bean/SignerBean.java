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

package it.eng.crypto.bean;

import java.security.Principal;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

/**
 * Bean di utilità che consente di memorizzare le informazioni relative a una singola firma. Vengono
 * memorizzati:
 * <ul>
 * <li>certificato di firma</li>
 * <li>emittente del certificato di firma</li>
 * <li>firmatario</li>
 * </ul>
 *
 * @author Stefano Zennaro
 *
 */
public class SignerBean {
    /*
     * Certificato di firma
     */

    private X509Certificate certificate;
    /*
     * Emittente del certificato di firma
     */
    private X500Principal iusser;
    /*
     * Firmatario
     */
    private Principal subject;

    /**
     * Recupera l'emittente del certificato di firma
     *
     * @return emittente del certificato di firma
     */
    public X500Principal getIusser() {
	return iusser;
    }

    /**
     * Definisce l'emittente del certificato di firma
     *
     * @param iusser emittente del certificato di firma
     */
    public void setIusser(X500Principal iusser) {
	this.iusser = iusser;
    }

    /**
     * Recupera il firmatario
     *
     * @return firmatario
     */
    public Principal getSubject() {
	return subject;
    }

    /**
     * Definisce il firmatario
     *
     * @param subject firmatario
     */
    public void setSubject(Principal subject) {
	this.subject = subject;
    }

    /**
     * Recupera il certificato di firma
     *
     * @return certificato di firma
     */
    public X509Certificate getCertificate() {
	return certificate;
    }

    /**
     * Definisce il certificato di firma
     *
     * @param certificate certificato di firma
     */
    public void setCertificate(X509Certificate certificate) {
	this.certificate = certificate;
    }

    public String toString() {
	// return "certificate:\n" + certificate + ",\nissuer:\n" + iusser + ",\nsubject:\n" +
	// subject;
	return "certificate:\n" + certificate + ",\nsubject:\n" + subject;
    }
}
