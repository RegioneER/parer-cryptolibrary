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

import java.io.File;

/**
 * Bean d'appoggio contenente il riferimento ai file sbustati e informazioni sul fatto che questi possano contenere a
 * loro volta delle firme
 * 
 * @author Stefano Zennaro
 *
 */
public class ContentBean {

    private File contentFile;
    private boolean possiblySigned = false;

    /**
     * Recupera il contenuto sbustato
     * 
     * @return il contenuto sbustato
     */
    public File getContentFile() {
        return contentFile;
    }

    /**
     * Definisce il contenuto sbustato
     * 
     * @param contentFile
     */
    public void setContentFile(File contentFile) {
        this.contentFile = contentFile;
    }

    /**
     * Restituisce true se il contenuto può essere ulteriormente firmato
     * 
     * @return
     */
    public boolean isPossiblySigned() {
        return possiblySigned;
    }

    /**
     * Definisce se il contenuto può essere ulteriormente firmato
     * 
     * @param possiblySigned
     */
    public void setPossiblySigned(boolean possiblySigned) {
        this.possiblySigned = possiblySigned;
    }

}
