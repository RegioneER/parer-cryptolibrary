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
