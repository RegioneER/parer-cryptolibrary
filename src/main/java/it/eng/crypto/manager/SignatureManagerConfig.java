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

package it.eng.crypto.manager;

import it.eng.crypto.manager.SignatureManager.CONFIGURATION;

import java.io.File;
import java.util.Date;

/**
 * Bean che descrive la configurazione per eseguire i controlli dei file firmati
 *
 * @author Stefano Zennaro
 *
 */
public class SignatureManagerConfig {

    /**
     * Tipo di contenuto EMBEDDED/DETACHED
     */
    public static final int EMBEDDED_CONTENT = 0;
    public static final int DETACHED_CONTENT = 1;

    public enum ContentType {

        EMBEDDED_CONTENT, DETACHED_CONTENT
    }

    private ContentType contentType;
    private File contentFile;
    private File signatureFile;
    private File timeStampFile;
    private File[] timeStampExtensions;
    private boolean isTimeStampEmbedded = true;
    private Date referenceDate;

    /**
     * Recupera il tipo di contenuto (EMBEDDED/DETACHED)
     *
     * @return
     */
    public ContentType getContentType() {
        return contentType;
    }

    /**
     * Definisce il tipo di contenuto (EMBEDDED/DETACHED)
     */
    public void setContentType(ContentType contentType) {
        this.contentType = contentType;
    }

    /**
     * Restituisce il file corrispondente al contenuto firmato
     *
     * @return
     */
    public File getContentFile() {
        return contentFile;
    }

    /**
     * Definisce il file corrispondente al contenuto firmato
     *
     * @param contentFile
     */
    public void setContentFile(File contentFile) {
        this.contentFile = contentFile;
    }

    /**
     * Recupera il file contenente la firma digitale
     *
     * @return
     */
    public File getSignatureFile() {
        return signatureFile;
    }

    /**
     * Definisce il file contenete la firma digitale
     *
     * @param signatureFile
     */
    public void setSignatureFile(File signatureFile) {
        this.signatureFile = signatureFile;
    }

    /**
     * Recupera il file contenente la marca temporale
     *
     * @return
     */
    public File getTimeStampFile() {
        return timeStampFile;
    }

    /**
     * Definisce il file contente la marca temporale
     *
     * @param timeStampFile
     */
    public void setTimeStampFile(File timeStampFile) {
        this.timeStampFile = timeStampFile;
    }

    /**
     * Recupera i file che corrispondono alla catena di estensioni della marca temporale
     *
     * @return
     */
    public File[] getTimeStampExtensions() {
        return timeStampExtensions;
    }

    /**
     * Definisce i file che corrispondono alla catena di estensioni della marca temporale
     *
     * @return
     */
    public void setTimeStampExtensions(File[] timeStampExtensions) {
        this.timeStampExtensions = timeStampExtensions;
    }

    /**
     * Restituisce true se la marca temporale è embedded
     *
     * @return
     */
    public boolean isTimeStampEmbedded() {
        return isTimeStampEmbedded;
    }

    /**
     * Definisce se la marca temporale è embedded nel file corrispondente alla firma digitale
     *
     * @param isTimeStampEmbedded
     */
    public void setTimeStampEmbedded(boolean isTimeStampEmbedded) {
        this.isTimeStampEmbedded = isTimeStampEmbedded;
    }

    CONFIGURATION getConfiguration() {
        switch (contentType) {
        case DETACHED_CONTENT:
            if (isTimeStampEmbedded) {
                return CONFIGURATION.CONFIG_4_5;
            } else {
                return CONFIGURATION.CONFIG_6;
            }
        default:
            if (isTimeStampEmbedded) {
                return CONFIGURATION.CONFIG_1_2;
            } else {
                return CONFIGURATION.CONFIG_3;
            }
        }
    }

    /**
     * Verifica se la configurazione attualmente settata è valida
     *
     * @return true se la configurazione attuale è valida
     */
    public boolean isValid() {
        CONFIGURATION config = getConfiguration();
        switch (config) {
        case CONFIG_1_2:
        case CONFIG_3:
            if (contentFile == null) {
                return false;
            }
            break;
        case CONFIG_4_5:
        case CONFIG_6:
            if (contentFile == null || signatureFile == null) {
                return false;
            }
            break;
        default:
            return false;
        }
        return true;
    }

    /**
     * @return the referenceDate
     */
    public Date getReferenceDate() {
        return referenceDate;
    }

    /**
     * @param referenceDate the referenceDate to set
     */
    public void setReferenceDate(Date referenceDate) {
        this.referenceDate = referenceDate;
    }
}
