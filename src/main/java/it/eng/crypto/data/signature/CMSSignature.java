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
import it.eng.crypto.data.type.SignerType;
import it.eng.crypto.utils.OIDsMapConstants;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Arrays;

/**
 * Implementa una firma digitale di tipo CMS (utilizzata nei formati P7M, M7M e CAdES)
 *
 * @author Stefano Zennaro
 */
public class CMSSignature implements ISignature {

    private SignerType formatoFirma;
    private SignerInformation signerInformation;
    // private X509Certificate certificate;
    private List<ISignature> counterSignatures;
    private SignerBean signerBean;
    // TEST
    private List<File> detachedFiles;
    private Date referenceDate;
    private Date dateTimeStamp;
    private String referenceDateType;

    public CMSSignature(SignerInformation signerInformation, X509Certificate certificate, SignerType formatoFirma) {
        this.formatoFirma = formatoFirma;
        this.detachedFiles = null;
        this.signerInformation = signerInformation;
        SignerBean signerBean = new SignerBean();
        signerBean.setCertificate(certificate);
        signerBean.setIusser(certificate.getIssuerX500Principal());
        signerBean.setSubject(certificate.getSubjectX500Principal());
        this.signerBean = signerBean;
        // this.certificate = certificate;
    }

    public CMSSignature(SignerInformation signerInformation, X509Certificate certificate, List<File> detachedFiles,
            SignerType formatoFirma) {
        this(signerInformation, certificate, formatoFirma);
        this.formatoFirma = formatoFirma;
        this.detachedFiles = detachedFiles;
    }

    public byte[] getSignatureBytes() {
        return signerInformation.getSignature();
    }

    public SignerBean getSignerBean() {
        return signerBean;
    }

    public ValidationInfos verify() {
        ValidationInfos validationInfos = new ValidationInfos();
        try {
            if (!signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
                    .build(signerBean.getCertificate().getPublicKey()))) {

                validationInfos.addError("La firma non corrisponde al contenuto firmato");
            }
        } catch (Exception e) {
            validationInfos.addError(e.getMessage());
        }

        return validationInfos;
    }

    public SignerInformation getSignerInformation() {
        return signerInformation;
    }

    public void setSignerInformation(SignerInformation signerInformation) {
        this.signerInformation = signerInformation;
        SignerId signerId = signerInformation.getSID();
        this.signerBean.setCertificate(signerId.getCertificate());
        // this.certificate = signerId.getCertificate();
    }

    public String toString() {
        return "Signature: " + signerInformation == null ? "" : getSignerBean().toString();
    }

    public void setCounterSignatures(List<ISignature> counterSignatures) {
        this.counterSignatures = counterSignatures;
    }

    public List<ISignature> getCounterSignatures() {
        return counterSignatures;
    }

    public List<File> getDetachedFiles() {
        return detachedFiles;
    }

    public void setDetachedFiles(List<File> detachedFiles) {
        this.detachedFiles = detachedFiles;
    }

    @Deprecated
    protected ValidationInfos verifyDetachedContent(SignerInformation signerInformation, InputStream detachedContent) {
        ValidationInfos validationInfos = new ValidationInfos();

        String digestAlgorithmOID = signerInformation.getDigestAlgOID();
        MessageDigest contentDigestAlgorithm;
        try {
            contentDigestAlgorithm = MessageDigest.getInstance(digestAlgorithmOID);

            // Impronta del contenuto esterno
            byte[] hashedDetachedData = null;
            // Impronta degli attributi firmati
            byte[] hashedSignedAttributes = null;
            // Contenuto decifrato della firma
            byte[] decodedSignature = null;
            // Attributo firmato digest
            byte[] digestSignedAttribute = null;

            byte[] buff = new byte[Byte.SIZE * 512];
            int length = -1;
            contentDigestAlgorithm.reset();
            while ((length = detachedContent.read(buff)) != -1) {
                contentDigestAlgorithm.update(buff, 0, length);
            }
            hashedDetachedData = contentDigestAlgorithm.digest();

            // hashedDetachedData = contentDigestAlgorithm.digest(detachedContent);
            AttributeTable signedAttributeTable = signerInformation.getSignedAttributes();
            if (signerInformation.getEncodedSignedAttributes() != null) {
                hashedSignedAttributes = contentDigestAlgorithm.digest(signerInformation.getEncodedSignedAttributes());
            }
            digestAlgorithmOID = signerInformation.getEncryptionAlgOID();
            byte[] signature = signerInformation.getSignature();
            Cipher cipher = null;
            String algorithmName = null;
            if (PKCSObjectIdentifiers.rsaEncryption.getId().equals(digestAlgorithmOID)) {
                algorithmName = "RSA/ECB/PKCS1Padding";
            } else if (PKCSObjectIdentifiers.sha1WithRSAEncryption.getId().equals(digestAlgorithmOID)) {
                algorithmName = "RSA/ECB/PKCS1Padding";
            } else {
                algorithmName = digestAlgorithmOID;
            }
            cipher = Cipher.getInstance(algorithmName, "BC");
            cipher.init(Cipher.DECRYPT_MODE, signerBean.getCertificate().getPublicKey());
            byte[] decryptedSignature = cipher.doFinal(signature);

            ASN1InputStream asn1is = new ASN1InputStream(decryptedSignature);
            ASN1Sequence asn1Seq = (ASN1Sequence) asn1is.readObject();

            Enumeration<? extends DERObject> objs = asn1Seq.getObjects();
            while (objs.hasMoreElements()) {
                DERObject derObject = objs.nextElement();
                if (derObject instanceof ASN1OctetString) {
                    ASN1OctetString octectString = (ASN1OctetString) derObject;
                    decodedSignature = octectString.getOctets();
                    break;
                }
            }
            boolean signatureVerified = Arrays.constantTimeAreEqual(decodedSignature, hashedSignedAttributes);
            if (!signatureVerified) {
                validationInfos
                        .addError("La firma non è valida: l'hash degli attributi firmati è " + hashedSignedAttributes
                                + " mentre la firma è stata apposta su un contenuto con hash: " + decodedSignature);
            } else {
                Attribute digestAttribute = signedAttributeTable.get(PKCSObjectIdentifiers.pkcs_9_at_messageDigest);
                ASN1Set values = digestAttribute.getAttrValues();
                DERObject derObject = values.getObjectAt(0).getDERObject();
                if (derObject instanceof ASN1OctetString) {
                    ASN1OctetString octectString = (ASN1OctetString) derObject;
                    digestSignedAttribute = octectString.getOctets();
                }

                boolean contentDigestVerified = Arrays.constantTimeAreEqual(hashedDetachedData, digestSignedAttribute);
                if (!contentDigestVerified) {
                    validationInfos.addError("La firma è valida ma non è associata al file corretto");
                }
            }
            asn1is.close();
        } catch (NoSuchAlgorithmException e) {
            validationInfos.addError(
                    "Impossibile validare la firma poichè l'algoritmo non è supportato: " + digestAlgorithmOID);
        } catch (IOException e) {
            validationInfos.addError("Errore durante la validazione della firma: " + e.getMessage());
        } catch (GeneralSecurityException e) {
            validationInfos.addError("Impossibile decifrare la firma: " + e.getMessage());
        }

        return validationInfos;
    }

    @Override
    public Date getDateSignature() {
        if (signerInformation != null && signerInformation.getSignedAttributes() != null
                && signerInformation.getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_signingTime) != null) {

            DERSet set = (DERSet) signerInformation.getSignedAttributes()
                    .get(PKCSObjectIdentifiers.pkcs_9_at_signingTime).getAttrValues();
            DERGeneralizedTime dergt = null;
            DERUTCTime dertime = null;
            Enumeration e = set.getObjects();
            while (e.hasMoreElements()) {
                Object o = e.nextElement();
                if (o instanceof DERGeneralizedTime) {
                    dergt = (DERGeneralizedTime) o;
                }
                if (o instanceof DERUTCTime) {
                    dertime = (DERUTCTime) o;
                }
            }
            try {
                if (dergt != null && !dergt.toString().isEmpty()) {
                    return dergt.getDate();
                }
                if (dertime != null && !dertime.toString().isEmpty()) {
                    return dertime.getDate();
                }

            } catch (ParseException ex) {
                return null;
            }
        }
        return null;

    }

    @Override
    public TimeStampToken getTimeStamp() {
        AttributeTable table = signerInformation.getUnsignedAttributes();
        if (table == null) {
            return null;
        }
        Attribute attribute = (Attribute) table.toHashtable().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        // Attribute attribute = (Attribute) table.toHashtable().get(new
        // DERObjectIdentifier("1.2.840.113549.1.9.16.2.47"));
        if (attribute != null && attribute.getAttrValues() != null) {
            TimeStampToken timestamptoken = null;
            try {
                timestamptoken = new TimeStampToken(
                        new CMSSignedData(attribute.getAttrValues().getObjectAt(0).getDERObject().getEncoded()));
            } catch (Exception e) {
                e.printStackTrace();
            }
            if (timestamptoken != null) {
                return timestamptoken;// .getTimeStampInfo().getGenTime();
            }
        }
        return null;

    }

    @Override
    public Date getReferenceDate() {

        return this.referenceDate;
    }

    public void setDateTimeStamp(Date dateTimeStamp) {
        this.dateTimeStamp = dateTimeStamp;
    }

    @Override
    public void setReferenceDate(Date referenceDate) {
        this.referenceDate = referenceDate;
    }

    @Override
    public String getSigAlgorithm() {
        return OIDsMapConstants.getDigestNames().get(this.signerInformation.getDigestAlgOID()) + "with"
                + OIDsMapConstants.getAlgorithmNames().get(this.signerInformation.getEncryptionAlgOID());

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
