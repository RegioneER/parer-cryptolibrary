/*
 * Engineering Ingegneria Informatica S.p.A.
 *
 * Copyright (C) 2023 Regione Emilia-Romagna
 * <p/>
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Affero General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 * <p/>
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package it.eng.crypto;

import java.io.Serializable;

/**
 * Classe che setta i parametri di configurazione del sistema
 *
 * @author Rigo Michele
 *
 * @version 0.1
 */
public class CryptoConfiguration implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 1L;
    /**
     * Schedulazione per il controllo della revoca dei certificati
     */
    private String scheduleCARevoke = null;
    /**
     * Schedulazione per l'aggiornamento dei certificati
     */
    private String scheduleCAUpdate = null;
    /**
     * URL di recupero dei certificati accreditati
     */
    private String qualifiedCertificatesURL = null;
    /**
     * Utente del proxy
     */
    private String proxyUser = null;
    /**
     * Password del proxy
     */
    private String proxyPassword = null;
    /**
     * Host del proxy
     */
    private String proxyHost = null;
    /**
     * Porta del proxy
     */
    private Integer proxyPort = null;
    /**
     * Dominio dell'utente per autenticazione NTLS
     */
    private String userDomain = null;
    /**
     * Host della macchina utente per autenticazione NTLS
     */
    private String userHost = null;

    /**
     * URL del servizio di timestamping
     */
    // private String TSAServiceURL = null;
    //
    //
    // private String TSAAuthScope = null;
    //
    //
    // /**
    // * Username per l'utilizzo del servizio di timestamping
    // */
    // private String TSAUser = null;
    //
    //
    // /**
    // * Password per l'utilizzo del servizio di timestamping
    // */
    // private String TSAPass = null;
    /**
     * Restituisce il campo di autenticazione del proxy criptato
     *
     * @return
     */
    public String getProxyAuth() {
        String auth = "";
        if (proxyUser != null && proxyPassword != null) {
            String authString = proxyUser + ":" + proxyPassword;
            auth = "Basic " + new String(new org.apache.commons.codec.binary.Base64().encode(authString.getBytes()));
        }
        return auth;
    }

    /**
     * Indica se il proxy è configurato o meno
     *
     * @return
     */
    public boolean isProxy() {
        boolean ret = false;
        if (proxyHost != null && proxyPort != null) {
            ret = true;
        }
        return ret;
    }

    /**
     * Indica se il proxy è configurato o meno
     *
     * @return
     */
    public boolean isNTLSAuth() {
        boolean ret = false;
        if (userDomain != null && userHost != null) {
            ret = true;
        }
        return ret;
    }

    // /**
    // * Indica se la TSA richiede o meno l'autenticazione
    // *
    // * @return
    // */
    // public boolean isTSAAuth() {
    // boolean ret = false;
    // if (TSAUser != null && TSAPass != null && TSAAuthScope != null
    // && !TSAUser.isEmpty() && !TSAPass.isEmpty() && !TSAAuthScope.isEmpty()) {
    // ret = true;
    // }
    // return ret;
    // }
    /**
     * Definisce il proxy d'accesso web
     *
     * @param proxyUser
     */
    public void setProxyUser(String proxyUser) {
        this.proxyUser = proxyUser;
    }

    /**
     * Definisce la password d'accesso al proxy
     *
     * @param proxyPassword
     */
    public void setProxyPassword(String proxyPassword) {
        this.proxyPassword = proxyPassword;
    }

    /**
     * Restituisce l'host del proxy
     *
     * @return
     */
    public String getProxyHost() {
        return proxyHost;
    }

    /**
     * Definisce l'host del proxy
     *
     * @param proxyHost
     */
    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    /**
     * Recupera la porta del proxy
     *
     * @return
     */
    public Integer getProxyPort() {
        return proxyPort;
    }

    /**
     * Definisce la porta del proxy
     *
     * @param proxyPort
     */
    public void setProxyPort(Integer proxyPort) {
        this.proxyPort = proxyPort;
    }

    /**
     * Recupera la schedulazione per il controllo della revoca dei certificati
     *
     * @return
     */
    public String getScheduleCARevoke() {
        return scheduleCARevoke;
    }

    /**
     * Definisce la schedulazione per il controllo della revoca dei certificati
     *
     * @param scheduleCARevoke
     */
    public void setScheduleCARevoke(String scheduleCARevoke) {
        this.scheduleCARevoke = scheduleCARevoke;
    }

    /**
     * Recupera ls schedulazione per l'aggiornamento dei certificati
     *
     * @return
     */
    public String getScheduleCAUpdate() {
        return scheduleCAUpdate;
    }

    /**
     * Definisce la schedulazione per l'aggiornamento dei certificati
     *
     * @param scheduleCAUpdate
     */
    public void setScheduleCAUpdate(String scheduleCAUpdate) {
        this.scheduleCAUpdate = scheduleCAUpdate;
    }

    /**
     * Recupera l'URL per reperire i certificati accreditati
     *
     * @return
     */
    public String getQualifiedCertificatesURL() {
        return qualifiedCertificatesURL;
    }

    /**
     * Definisce l'URL per reperire i certificati accreditati
     *
     * @param qualifiedCertificatesURL
     */
    public void setQualifiedCertificatesURL(String qualifiedCertificatesURL) {
        this.qualifiedCertificatesURL = qualifiedCertificatesURL;
    }

    /**
     * Definisce l'utente per l'accesso al proxy
     *
     * @return
     */
    public String getProxyUser() {
        return proxyUser;
    }

    /**
     * Recupera l'utente per l'accesso al proxy
     *
     * @return
     */
    public String getProxyPassword() {
        return proxyPassword;
    }

    public String getUserHost() {
        return userHost;
    }

    public void setUserHost(String userHost) {
        this.userHost = userHost;
    }

    public String getUserDomain() {
        return userDomain;
    }

    public void setUserDomain(String userDomain) {
        this.userDomain = userDomain;
    }
    // public String getTSAServiceURL() {
    // return TSAServiceURL;
    // }
    //
    // public void setTSAServiceURL(String TSAServiceURL) {
    // this.TSAServiceURL = TSAServiceURL;
    // }
    //
    // public String getTSAPass() {
    // return TSAPass;
    // }
    //
    // public void setTSAPass(String TSAPass) {
    // this.TSAPass = TSAPass;
    // }
    //
    // public String getTSAUser() {
    // return TSAUser;
    // }
    //
    // public void setTSAUser(String TSAUser) {
    // this.TSAUser = TSAUser;
    // }
    //
    // public String getTSAAuthScope() {
    // return TSAAuthScope;
    // }
    //
    // public void setTSAAuthScope(String TSAAuthScope) {
    // this.TSAAuthScope = TSAAuthScope;
    // }
}
