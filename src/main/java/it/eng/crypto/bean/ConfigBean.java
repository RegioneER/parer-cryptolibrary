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

import java.io.Serializable;
import java.math.BigDecimal;

/**
 * Bean contenente le configurazioni dei certificati e delle CRL
 *
 * @author Rigo Michele
 */
public class ConfigBean implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 1L;
    private String subjectDN;
    private String crlURL;
    private String schedule;
    private String keyId;
    private BigDecimal niOrdUrlDistribCrl;

    /**
     * Recupera il nome dell'entità associata al certificato così come riportato nel Distinguished
     * Name (RFC2459)
     *
     * @return
     */
    public String getSubjectDN() {
        return subjectDN;
    }

    /**
     * Definisce il nome dell'entità associata al certificato
     *
     * @return
     */
    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    /**
     * Recupera l'URL da cui scaricare la CRL
     *
     * @return
     */
    public String getCrlURL() {
        return crlURL;
    }

    /**
     * Definisce l'URL da cui scaricare la CRL
     *
     * @param crlURL
     */
    public void setCrlURL(String crlURL) {
        this.crlURL = crlURL;
    }

    /**
     * Recupera il pattern di schedulazione configurato
     *
     * @return
     */
    public String getSchedule() {
        return schedule;
    }

    /**
     * Definisce un pattern di schedulazione
     *
     * @param schedule
     */
    public void setSchedule(String schedule) {
        this.schedule = schedule;
    }

    public BigDecimal getNiOrdUrlDistribCrl() {
        return niOrdUrlDistribCrl;
    }

    public void setNiOrdUrlDistribCrl(BigDecimal niOrdUrlDistribCrl) {
        this.niOrdUrlDistribCrl = niOrdUrlDistribCrl;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }
}
