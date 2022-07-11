package it.eng.crypto.controller.exception;

import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import java.util.Map;

/**
 * Eccezione specializzata per il processo di controllo dei file firmati
 *
 * @author Rigo Michele
 *
 */
public class ExceptionController extends Exception {

    Map<String, ValidationInfos> complianceChecks;

    public ExceptionController(String message) {
        super(message);
    }

    public ExceptionController(Exception e) {
        super(e);
    }

    public ExceptionController(Exception e, Map<String, ValidationInfos> complianceChecks) {
        super(e);
        this.complianceChecks = complianceChecks;
    }

    public Map<String, ValidationInfos> getComplianceChecks() {
        return complianceChecks;
    }
}
