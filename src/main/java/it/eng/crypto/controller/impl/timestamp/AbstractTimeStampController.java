package it.eng.crypto.controller.impl.timestamp;

import it.eng.crypto.controller.bean.InputBean;
import it.eng.crypto.controller.bean.InputTimeStampBean;
import it.eng.crypto.controller.bean.OutputBean;
import it.eng.crypto.controller.bean.OutputTimeStampBean;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.controller.impl.AbstractController;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Locale;

public abstract class AbstractTimeStampController extends AbstractController {

    public boolean execute(InputBean input, OutputBean output) throws ExceptionController {
        if (input instanceof InputTimeStampBean && output instanceof OutputTimeStampBean)
            return execute((InputTimeStampBean) input, (OutputTimeStampBean) output);
        return false;
    }

    protected DateFormat dateFormatter = SimpleDateFormat.getDateTimeInstance(DateFormat.LONG, DateFormat.LONG,
            Locale.ITALY);

    public abstract boolean execute(InputTimeStampBean input, OutputTimeStampBean output) throws ExceptionController;

}
