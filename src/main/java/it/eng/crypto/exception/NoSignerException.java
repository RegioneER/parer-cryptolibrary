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

/**
 * Eccezione specializzata per il mancato recupero della classe Signer
 *
 * @author Rigo Michele
 *
 * @verison 0.1 14/04/2010
 */
public class NoSignerException extends Exception {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public NoSignerException() {
        super();
        // TODO Auto-generated constructor stub
    }

    public NoSignerException(String message, Throwable cause) {
        super(message, cause);
        // TODO Auto-generated constructor stub
    }

    public NoSignerException(String message) {
        super(message);
        // TODO Auto-generated constructor stub
    }

    public NoSignerException(Throwable cause) {
        super(cause);
        // TODO Auto-generated constructor stub
    }
}
