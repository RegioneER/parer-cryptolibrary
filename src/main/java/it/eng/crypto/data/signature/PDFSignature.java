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

import it.eng.crypto.bean.SignerBean;
import it.eng.crypto.controller.bean.ValidationInfos;

import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.itextpdf.text.pdf.PdfPKCS7;
import it.eng.crypto.data.type.SignerType;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * Implementa una firma digitale di tipo PDF (utilizzata nel formato PAdES)
 *
 * @author Stefano Zennaro
 */
public class PDFSignature implements ISignature {

    private SignerType formatoFirma;
    private PdfPKCS7 pkcs7;
    private List<ISignature> counterSignatures;
    private SignerBean signerBean;
    private Date dateTimeStamp;
    private Date referenceDate;
    private String referenceDateType;
    // private CMSSignedData cms;
    private byte[] signature;

    public PDFSignature(PdfPKCS7 pkcs, byte[] signature, SignerType formatoFirma) {
        this.formatoFirma = formatoFirma;
        // this.cms = cms;
        this.signature = signature;
        this.pkcs7 = pkcs;
        this.signerBean = new SignerBean();
        X509Certificate certificate = pkcs7.getSigningCertificate();
        signerBean.setCertificate(certificate);
        signerBean.setIusser(certificate.getIssuerX500Principal());
        signerBean.setSubject(certificate.getSubjectX500Principal());
        counterSignatures = new ArrayList<ISignature>();
    }

    /*
     * TODO: da implementare..
     */
    public List<ISignature> getCounterSignatures() {
        return counterSignatures;
    }

    public byte[] getSignatureBytes() {
        // TODO : il byte[] della firma è ottenibile solo utilizzando BC (La firma è nel campo privato "byte[] digest"
        // contenuto nella classe PdfPCKS7 di iText): performance e uso risorse non ottimali

        // Verificare se con firme multiple dal dizionario viene ritornata solo la firma rappresentata da questo oggetto

        return signature;// ((List<SignerInformation>) cms.getSignerInfos().getSigners()).get(0).getSignature();

        // return pdfDict.get(PdfName.CONTENTS).getBytes();
    }

    public SignerBean getSignerBean() {
        return signerBean;
    }

    public ValidationInfos verify() {
        ValidationInfos validationInfos = new ValidationInfos();
        boolean result = false;
        try {
            result = pkcs7.verify();
        } catch (SignatureException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        if (!result) {
            validationInfos.addError("La firma non corrisponde al contenuto firmato");
        }
        return validationInfos;
    }

    @Override
    public Date getDateSignature() {
        if (pkcs7.getSignDate() != null) {
            return pkcs7.getSignDate().getTime();
        } else {
            return null;
        }

    }

    @Override
    public TimeStampToken getTimeStamp() {
        return pkcs7.getTimeStampToken();// getTimeStampDate().getTime();

    }

    @Override
    public Date getReferenceDate() {
        return this.referenceDate;
    }

    @Override
    public void setReferenceDate(Date referenceDate) {
        this.referenceDate = referenceDate;
    }

    /**
     * Ritorna l'algoritmo di firma; se non presente nell'oggetto tornato da iText torna SHA1withRSA. L'algoritmo non è
     * presente quando le firme PDF sono realizzate con un subfilter di tipo adbe.x509.rsa_sha1
     *
     * @return l'algoritmo di firma
     */
    @Override
    public String getSigAlgorithm() {
        String alg = this.pkcs7.getDigestAlgorithm();
        if (this.pkcs7.getHashAlgorithm() == null) {
            alg = "SHA1withRSA";
        }
        return alg;
    }

    @Override
    public String getReferenceDateType() {
        return this.referenceDateType;
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
