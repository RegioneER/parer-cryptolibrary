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
import java.util.Map;

/**
 * Classe che setta i parametri di configurazione per una TSA
 *
 * @author Rigo Michele
 * 
 * @version 0.1
 */
public class TSAConfiguration {

    public TSAConfiguration(Map<String, String> map) {
        TSAServiceURL = map.get("TSAServiceURL");
        TSAAuthScope = map.get("TSAAuthScope");
        TSAUser = map.get("TSAUser");
        TSAPass = map.get("TSAPass");
    }

    /**
     * URL del servizio di timestamping
     */
    private String TSAServiceURL = null;
    private String TSAAuthScope = null;
    /**
     * Username per l'utilizzo del servizio di timestamping
     */
    private String TSAUser = null;
    /**
     * Password per l'utilizzo del servizio di timestamping
     */
    private String TSAPass = null;

    /**
     * Indica se la TSA richiede o meno l'autenticazione
     *
     * @return
     */
    public boolean isTSAAuth() {
        boolean ret = false;
        if (TSAUser != null && TSAPass != null && TSAAuthScope != null && !TSAUser.isEmpty() && !TSAPass.isEmpty()
                && !TSAAuthScope.isEmpty()) {
            ret = true;
        }
        return ret;
    }

    public String getTSAServiceURL() {
        return TSAServiceURL;
    }

    public void setTSAServiceURL(String TSAServiceURL) {
        this.TSAServiceURL = TSAServiceURL;
    }

    public String getTSAPass() {
        return TSAPass;
    }

    public void setTSAPass(String TSAPass) {
        this.TSAPass = TSAPass;
    }

    public String getTSAUser() {
        return TSAUser;
    }

    public void setTSAUser(String TSAUser) {
        this.TSAUser = TSAUser;
    }

    public String getTSAAuthScope() {
        return TSAAuthScope;
    }

    public void setTSAAuthScope(String TSAAuthScope) {
        this.TSAAuthScope = TSAAuthScope;
    }
}
