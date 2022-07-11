package it.eng.crypto.controller.impl.signature;

import it.eng.crypto.controller.bean.InputBean;
import it.eng.crypto.controller.bean.InputSignerBean;
import it.eng.crypto.controller.bean.OutputBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.controller.impl.AbstractController;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Locale;

/**
 * Definisce la classe di base per l'implementazione di un {@link it.eng.crypto.controller.ISignerController}
 * 
 * @author Administrator
 *
 */
public abstract class AbstractSignerController extends AbstractController {
    /**
     * Indica se occorre effettuare i controlli anche sulle controfirme (default = true)
     */
    protected boolean performCounterSignaturesCheck = true;

    protected DateFormat dateFormatter = SimpleDateFormat.getDateTimeInstance(DateFormat.LONG, DateFormat.LONG,
            Locale.ITALY);

    /**
     * Restituisce true se occorre effettuare i controlli anche sulle controfirme
     */
    public boolean isPerformCounterSignaturesCheck() {
        return performCounterSignaturesCheck;
    }

    /**
     * Definisce se occorre effettuare i controlli anche sulle controfirme
     * 
     * @param performCounterSignaturesCheck
     */
    public void setPerformCounterSignaturesCheck(boolean performCounterSignaturesCheck) {
        this.performCounterSignaturesCheck = performCounterSignaturesCheck;
    }

    public boolean execute(InputBean input, OutputBean output) throws ExceptionController {
        if (input instanceof InputSignerBean && output instanceof OutputSignerBean)
            return execute((InputSignerBean) input, (OutputSignerBean) output);
        return false;
    }

    public abstract boolean execute(InputSignerBean input, OutputSignerBean output) throws ExceptionController;

}
