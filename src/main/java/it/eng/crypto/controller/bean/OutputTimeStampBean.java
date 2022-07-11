package it.eng.crypto.controller.bean;

import it.eng.crypto.data.AbstractSigner;

import java.util.List;
import java.util.Map;

public class OutputTimeStampBean extends OutputBean {

    List<DocumentAndTimeStampInfoBean> documentAndTimeStampInfos;
    AbstractSigner signer;
    Map<String, ValidationInfos> complianceChecks;

    /**
     * @return the documentAndTimeStampInfos
     */
    public List<DocumentAndTimeStampInfoBean> getDocumentAndTimeStampInfos() {
        return documentAndTimeStampInfos;
    }

    /**
     * @param documentAndTimeStampInfos
     *            the documentAndTimeStampInfos to set
     */
    public void setDocumentAndTimeStampInfos(List<DocumentAndTimeStampInfoBean> documentAndTimeStampInfos) {
        this.documentAndTimeStampInfos = documentAndTimeStampInfos;
    }

    /**
     * @return the signer
     */
    public AbstractSigner getSigner() {
        return signer;
    }

    /**
     * @param signer
     *            the signer to set
     */
    public void setSigner(AbstractSigner signer) {
        this.signer = signer;
    }

    public Map getComplianceChecks() {
        return complianceChecks;
    }

    public void setComplianceChecks(Map complianceChecks) {
        this.complianceChecks = complianceChecks;
    }
}
