package it.eng.crypto.controller.bean;

import java.io.File;
import java.util.Date;

public class InputTimeStampBean extends InputBean {

    /**
     * Marca temporale embedded
     */
    private File timeStampWithContentFile;

    /**
     * File contenente la marca temporale detached
     */
    private File timeStampFile;

    /**
     * Contenuto marcato
     */
    private File contentFile;

    /**
     * Catena delle estensioni della marca temporale
     */
    private File[] timeStampExtensionsChain;

    /**
     * Data di riferimento per la verifica della validità dell'ultima marca temporale
     */
    private Date referenceDate;

    /**
     * @return the timeStampWithContentFile
     */
    public File getTimeStampWithContentFile() {
        return timeStampWithContentFile;
    }

    /**
     * @param timeStampWithContentFile
     *            the timeStampWithContentFile to set
     */
    public void setTimeStampWithContentFile(File timeStampWithContentFile) {
        this.timeStampWithContentFile = timeStampWithContentFile;
    }

    /**
     * @return the timeStampFile
     */
    public File getTimeStampFile() {
        return timeStampFile;
    }

    /**
     * @param timeStampFile
     *            the timeStampFile to set
     */
    public void setTimeStampFile(File timeStampFile) {
        this.timeStampFile = timeStampFile;
    }

    /**
     * @return the contentFile
     */
    public File getContentFile() {
        return contentFile;
    }

    /**
     * @param contentFile
     *            the contentFile to set
     */
    public void setContentFile(File contentFile) {
        this.contentFile = contentFile;
    }

    /**
     * @return the timeStampExtensionsChain
     */
    public File[] getTimeStampExtensionsChain() {
        return timeStampExtensionsChain;
    }

    /**
     * @param timeStampExtensionsChain
     *            the timeStampExtensionsChain to set
     */
    public void setTimeStampExtensionsChain(File[] timeStampExtensionsChain) {
        this.timeStampExtensionsChain = timeStampExtensionsChain;
    }

    /**
     * @return the referenceDate
     */
    public Date getReferenceDate() {
        return referenceDate;
    }

    /**
     * @param referenceDate
     *            the referenceDate to set
     */
    public void setReferenceDate(Date referenceDate) {
        this.referenceDate = referenceDate;
    }

}
