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

package it.eng.crypto.exception;

/**
 * Eccezione specializzata per lo storage
 *
 * @author Rigo Michele
 *
 * @verison 0.1 14/04/2010
 */
public class CryptoStorageException extends Exception {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public CryptoStorageException() {
        super();
    }

    public CryptoStorageException(String arg0, Throwable arg1) {
        super(arg0, arg1);
    }

    public CryptoStorageException(String arg0) {
        super(arg0);
    }

    public CryptoStorageException(Throwable arg0) {
        super(arg0);
    }
}
