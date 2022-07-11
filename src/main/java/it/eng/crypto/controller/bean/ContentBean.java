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
