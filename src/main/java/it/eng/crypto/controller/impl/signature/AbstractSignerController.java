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
