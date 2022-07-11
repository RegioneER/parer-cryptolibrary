package it.eng.crypto.exception;

import it.eng.crypto.controller.bean.ValidationInfos;
import java.util.Map;

/**
 * Eccezione specializzata per la firma
 *
 * @author Rigo Michele
 * 
 * @verison 0.1 14/04/2010
 */
public class CryptoSignerException extends Exception {

    /**
     *
     */
    private static final long serialVersionUID = 1L;
    Map<String, ValidationInfos> complianceChecks;

    public CryptoSignerException() {
        super();
    }

    public CryptoSignerException(String arg0, Throwable arg1) {
        super(arg0, arg1);
    }

    public CryptoSignerException(String arg0) {
        super(arg0);
    }

    public CryptoSignerException(String arg0, Map<String, ValidationInfos> complianceChecks) {
        super(arg0);
        this.complianceChecks = complianceChecks;
    }

    public CryptoSignerException(Throwable arg0) {
        super(arg0);
    }

    public Map<String, ValidationInfos> getComplianceChecks() {
        return complianceChecks;
    }
}