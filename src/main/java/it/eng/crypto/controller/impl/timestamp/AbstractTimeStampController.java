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
