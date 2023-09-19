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

package it.eng.crypto.controller.bean;

public class MessageProperty {

    private String errorContext;

    private int errorCode;

    private String errorMessage;

    /**
     * @return the errorContext
     */
    public String getErrorContext() {
        return errorContext;
    }

    /**
     * @param errorContext
     *            the errorContext to set
     */
    public void setErrorContext(String errorContext) {
        this.errorContext = errorContext;
    }

    /**
     * @return the errorCode
     */
    public int getErrorCode() {
        return errorCode;
    }

    /**
     * @param errorCode
     *            the errorCode to set
     */
    public void setErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }

    /**
     * @return the errorKey
     */
    public String getErrorKey() {
        return errorMessage;
    }

    /**
     * @param errorKey
     *            the errorKey to set
     */
    public void setErrorKey(String errorKey) {
        this.errorMessage = errorKey;
    }

    public String toString() {
        return this.errorMessage;
    }

}
