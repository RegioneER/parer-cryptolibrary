package it.eng.crypto.controller.bean;

import it.eng.crypto.data.AbstractSigner;

import java.io.File;
import java.security.cert.CRL;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Bean contenente tutte le proprietà di input del documento firmato da analizzare. Le informazioni contenute sono le
 * seguenti:
 * <ul>
 * <li>documentAndTimeStampInfo: informazioni riguardanti il timestamp associato al documento firmato</li>
 * <li>referenceDate: data di riferimento temporale rispetto alla quale validare i certificati di firma</li>
 * <li>signer: istanza della classe per l'estrazione e verifica delle firme contenute</li>
 * <li>envelope: file contenente la busta del documento firmato</li>
 * <li>detachedFile: eventuale riferimento al contenuto sbustato</li>
 * <li>crl: crl in input</li>
 * <li>checks: flag dei controlli da effettuare</li>
 * </ul>
 *
 * @author Rigo Michele
 *
 */
public class InputSignerBean extends InputBean {

    List<DocumentAndTimeStampInfoBean> validTimeStampInfo;
    DocumentAndTimeStampInfoBean documentAndTimeStampInfo;
    Date referenceDate;
    AbstractSigner signer;
    File envelope;
    File detachedFile;
    Boolean useSigninTimeAsReferenceDate;
    Boolean useExternalReferenceTime;
    Boolean useExternalTsdTsrM7MEnvelop;
    private String referenceDateType;

    /**
     * Recupera le informazioni riguardanti il timestamp associato al documento firmato
     *
     * @return informazioni riguardanti il timestamp associato al documento firmato
     */
    public DocumentAndTimeStampInfoBean getDocumentAndTimeStampInfo() {
        return documentAndTimeStampInfo;
    }

    /**
     * Definisce le informazioni riguardanti il timestamp associato al documento firmato
     *
     * @param documentAndTimeStampInfo
     */
    public void setDocumentAndTimeStampInfo(DocumentAndTimeStampInfoBean documentAndTimeStampInfo) {
        this.documentAndTimeStampInfo = documentAndTimeStampInfo;
    }

    /**
     * Recupera il file contenente la busta del documento firmato
     *
     * @return
     */
    public File getEnvelope() {
        return envelope;
    }

    /**
     * Definisce il file contenente la busta del documento firmato
     *
     * @param envelope
     */
    public void setEnvelope(File envelope) {
        this.envelope = envelope;
    }

    /**
     * Recupera il riferimento al contenuto sbustato (detached)
     *
     * @return
     */
    public File getDetachedFile() {
        return detachedFile;
    }

    /**
     * Definisce il riferimento al contenuto sbustato (detached)
     *
     * @param detachedFile
     */
    public void setDetachedFile(File detachedFile) {
        this.detachedFile = detachedFile;
    }

    /**
     * Recupera l'istanza della classe per l'estrazione e verifica delle firme contenute
     *
     * @return
     */
    public AbstractSigner getSigner() {
        return signer;
    }

    /**
     * Definisce l'istanza della classe per l'estrazione e verifica delle firme contenute
     *
     * @param signer
     */
    public void setSigner(AbstractSigner signer) {
        this.signer = signer;
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

    public List<DocumentAndTimeStampInfoBean> getValidTimeStampInfo() {
        return validTimeStampInfo;
    }

    public void setValidTimeStampInfo(List<DocumentAndTimeStampInfoBean> validTimeStampInfo) {
        this.validTimeStampInfo = validTimeStampInfo;
    }

    public boolean getUseSigninTimeAsReferenceDate() {
        return useSigninTimeAsReferenceDate;
    }

    public void setUseSigninTimeAsReferenceDate(boolean useSigninTimeAsReferenceDate) {
        this.useSigninTimeAsReferenceDate = useSigninTimeAsReferenceDate;
    }

    public String getReferenceDateType() {
        return this.referenceDateType;
    }

    public void setReferenceDateType(String referenceDateType) {
        this.referenceDateType = referenceDateType;
    }

    public Boolean getUseExternalReferenceTime() {
        return useExternalReferenceTime;
    }

    public void setUseExternalReferenceTime(Boolean useExternalReferenceTime) {
        this.useExternalReferenceTime = useExternalReferenceTime;
    }

    public Boolean getUseExternalTsdTsrM7MEnvelop() {
        return useExternalTsdTsrM7MEnvelop;
    }

    public void setUseExternalTsdTsrM7MEnvelop(Boolean useExternalTsdTsrM7MEnvelop) {
        this.useExternalTsdTsrM7MEnvelop = useExternalTsdTsrM7MEnvelop;
    }
}
