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