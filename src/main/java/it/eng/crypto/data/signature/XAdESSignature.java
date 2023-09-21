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

package it.eng.crypto.data.signature;

import es.mityc.firmaJava.libreria.xades.ResultadoValidacion;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.apache.xml.security.signature.XMLSignature;
import javax.xml.crypto.dsig.XMLValidateContext;

import it.eng.crypto.bean.SignerBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.data.type.SignerType;
import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * Implementa una firma digitale di tipo XML (utilizzata nel formato XAdES)
 *
 * @author Stefano Zennaro
 */
public class XAdESSignature implements ISignature {

    private SignerType formatoFirma;
    private XMLSignature signature;
    private X509Certificate certificate;
    private XMLValidateContext validateContext;
    private List<ISignature> counterSignatures;
    private Date referenceDate;
    private ResultadoValidacion validationResult;
    private String referenceDateType;

    public XAdESSignature(XMLSignature signature, XMLValidateContext validateContext, X509Certificate certificate,
            ResultadoValidacion validationResult, SignerType formatoFirma) {
        this.formatoFirma = formatoFirma;
        this.signature = signature;
        this.validateContext = validateContext;
        this.certificate = certificate;
        this.validationResult = validationResult;
    }

    public byte[] getSignatureBytes() {
        try {
            return signature.getSignatureValue();
        } catch (XMLSignatureException ex) {
            ex.printStackTrace();
            return null;
        }
    }

    public SignerBean getSignerBean() {
        SignerBean signerBean = new SignerBean();
        signerBean.setCertificate(this.certificate);
        signerBean.setIusser(this.certificate.getIssuerX500Principal());
        signerBean.setSubject(this.certificate.getSubjectX500Principal());
        return signerBean;
    }

    public ValidationInfos verify() {
        ValidationInfos validationInfos = new ValidationInfos();
        try {
            if (!signature.checkSignatureValue(certificate)) {
                validationInfos.addError("La firma non corrisponde al contenuto firmato");
            }
        } catch (XMLSignatureException ex) {
            validationInfos.addError(ex.getMessage());
        }
        return validationInfos;
    }

    public XMLSignature getSignature() {
        return signature;
    }

    public void setSignature(XMLSignature signature) {
        this.signature = signature;
    }

    public void setCounterSignatures(List<ISignature> counterSignatures) {
        this.counterSignatures = counterSignatures;
    }

    public List<ISignature> getCounterSignatures() {
        return counterSignatures;
    }

    @Override
    public Date getDateSignature() {
        if (validationResult.getDatosFirma() != null) {
            return validationResult.getDatosFirma().getFechaFirma();
        } else {
            return null;
        }
    }

    @Override
    public TimeStampToken getTimeStamp() {

        if (validationResult.getDatosFirma().getDatosSelloTiempo() != null
                && !validationResult.getDatosFirma().getDatosSelloTiempo().isEmpty()) {
            return validationResult.getDatosFirma().getDatosSelloTiempo().get(0).getTst();
        } else {
            return null;
        }

    }

    @Override
    public Date getReferenceDate() {
        return this.referenceDate;
    }

    @Override
    public void setReferenceDate(Date referenceDate) {
        this.referenceDate = referenceDate;
    }

    @Override
    public String getSigAlgorithm() {
        return signature.getSignedInfo().getSignatureMethodURI();
    }

    @Override
    public String getReferenceDateType() {
        return referenceDateType;
    }

    @Override
    public void setReferenceDateType(String referenceDateType) {
        this.referenceDateType = referenceDateType;
    }

    public SignerType getFormatoFirma() {
        return formatoFirma;
    }

    public void setFormatoFirma(SignerType formatoFirma) {
        this.formatoFirma = formatoFirma;
    }
}
