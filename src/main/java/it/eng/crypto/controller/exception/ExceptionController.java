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
