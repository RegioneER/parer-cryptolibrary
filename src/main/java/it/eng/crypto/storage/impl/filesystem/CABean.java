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

package it.eng.crypto.storage.impl.filesystem;

import java.io.Serializable;

/**
 * Bean di appoggio allo storage del FileSystemCAStorage che wrappa gli attributi di una
 * Certification Authority da salvare
 *
 * @author Rigo Michele
 *
 * @version 0.1
 */
class CABean implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 1L;
    private String subjectDN;
    private Boolean active = true;
    private String filePath;

    /**
     * Recupera il riferimento al file
     *
     * @return
     */
    public String getFilePath() {
	return filePath;
    }

    /**
     * Definisce il riferimento al file
     *
     * @param filePath
     */
    public void setFilePath(String filePath) {
	this.filePath = filePath;
    }

    /**
     * Recupera il nome dell'entità associata al certificato così come riportato nel Distinguished
     * Name (RFC2459)
     *
     * @return
     */
    public String getSubjectDN() {
	return subjectDN;
    }

    /**
     * Definisce il nome dell'entità associata al certificato così come riportato nel Distinguished
     * Name (RFC2459)
     *
     * @return
     */
    public void setSubjectDN(String subjectDN) {
	this.subjectDN = subjectDN;
    }

    /**
     * Restituisce true se il certificato è attivo
     *
     * @return
     */
    public boolean isActive() {
	return active;
    }

    /**
     * Definisce se il certificato è attivo
     *
     * @param active
     */
    public void setActive(boolean active) {
	this.active = active;
    }
}
