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

package it.eng.crypto.controller.bean;

import java.security.cert.CRL;
import java.util.HashMap;
import java.util.Map;

public class InputBean {

    // Mappa dei flag indicanti i controlli da effettuare
    Map<String, Boolean> checks;
    // Lista delle crl
    private CRL crl;

    // Timeout connessione HTTP per recupero CRL
    private int httpCrlTimeoutConnection;

    // Timeout socket HTTP per recupero CRL
    private int httpCrlSocketTimeout;
    
    // Timeout connessione LDAP per recupero CRL
    private int ldapCrlTimeoutConnection;


    private boolean checkCAOnline;


    /**
     * Recupera il valore di un flag di controllo
     *
     * @param property nome del flag da recuperare
     *
     * @return il valore del flag
     */
    public Boolean getFlag(String property) {
        if (checks != null && checks.containsKey(property)) {
            return checks.get(property);
        }
        return false;
    }

    /**
     * Definisce il valore di un flag di controllo
     *
     * @param property nome del flag da settare
     * @param value    valore del flag
     */
    public void setFlag(String property, Boolean value) {
        if (checks == null) {
            checks = new HashMap<String, Boolean>();
        }
        checks.put(property, value);
    }

    /**
     * Recupera i flag dei controlli da effettuare
     *
     * @return
     */
    public Map<String, Boolean> getChecks() {
        return checks;
    }

    /**
     * Definisce i flag dei controlli da effettuare
     *
     * @param checks
     */
    public void setChecks(Map<String, Boolean> checks) {
        this.checks = checks;
    }

    /**
     * Recupera la crl in input
     *
     * @return
     */
    public CRL getCrl() {
        return crl;
    }

    /**
     * Definisce la crl in input
     *
     * @param crl
     */
    public void setCrl(CRL crl) {
        this.crl = crl;
    }
    
    public boolean isCheckCAOnline() {
        return checkCAOnline;
    }

    public void setCheckCAOnline(boolean checkCAOnline) {
        this.checkCAOnline = checkCAOnline;
    }
    
    // Getter e Setter timeout connessione CRL
    public int getHttpCrlTimeoutConnection() {
	return httpCrlTimeoutConnection;
    }

    public void setHttpCrlTimeoutConnection(int httpCrlTimeoutConnection) {
	this.httpCrlTimeoutConnection = httpCrlTimeoutConnection;
    }

    public int getLdapCrlTimeoutConnection() {
	return ldapCrlTimeoutConnection;
    }

    public void setLdapCrlTimeoutConnection(int ldapCrlTimeoutConnection) {
	this.ldapCrlTimeoutConnection = ldapCrlTimeoutConnection;
    }

    public int getHttpCrlSocketTimeout() {
	return httpCrlSocketTimeout;
    }

    public void setHttpCrlSocketTimeout(int httpCrlSocketTimeout) {
	this.httpCrlSocketTimeout = httpCrlSocketTimeout;
    }



}
