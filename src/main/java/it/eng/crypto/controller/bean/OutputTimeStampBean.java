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
     * @param documentAndTimeStampInfos the documentAndTimeStampInfos to set
     */
    public void setDocumentAndTimeStampInfos(
            List<DocumentAndTimeStampInfoBean> documentAndTimeStampInfos) {
        this.documentAndTimeStampInfos = documentAndTimeStampInfos;
    }

    /**
     * @return the signer
     */
    public AbstractSigner getSigner() {
        return signer;
    }

    /**
     * @param signer the signer to set
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
