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
package it.eng.crypto.controller.bean;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

/**
 *
 * @author quaranta_m
 */
public class TrustChainCheck {

    private X509Certificate cerificate;
    private X509CRL crl;
    private boolean isRootCa;

    public X509Certificate getCerificate() {
	return cerificate;
    }

    public void setCerificate(X509Certificate cerificate) {
	this.cerificate = cerificate;
    }

    public X509CRL getCrl() {
	return crl;
    }

    public void setCrl(X509CRL crl) {
	this.crl = crl;
    }

    public boolean isIsRootCa() {
	return isRootCa;
    }

    public void setIsRootCa(boolean isRootCa) {
	this.isRootCa = isRootCa;
    }

}
