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

package it.eng.crypto.data;

import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.data.signature.ISignature;
import it.eng.crypto.data.signature.PDFSignature;
import it.eng.crypto.data.type.SignerType;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TimeStampToken;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfPKCS7;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfString;
import it.eng.crypto.utils.VerificheEnums.EsitoControllo;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

/**
 * Implementa i controlli su firme di tipo PAdES. Il contenuto di un file è riconosciuto se implementa le specifiche
 * ETSI TS 102 778-1
 *
 * @author Stefano Zennaro
 */
public class PdfSigner extends AbstractSigner {

    private AcroFields acroFields;
    private Map<String, PdfPKCS7> signaturesByName;

    public boolean isSignedType(File file, ValidationInfos complianceCheck) {
        boolean signed = false;
        PdfReader reader = null;
        try {
            // Al PdfReader bisogna passare direttamente il file, consuma meno risorse
            // stream = FileUtils.openInputStream(file);
            // signed = isSignedType(stream,complianceCheck);
            // Resetto il signer
            reset();
            acroFields = null;
            signaturesByName = null;

            signaturesByName = new HashMap<String, PdfPKCS7>();
            try {
                reader = new PdfReader(file.getAbsolutePath());
                acroFields = reader.getAcroFields();
                ArrayList<String> names = acroFields.getSignatureNames();
                for (String name : names) {
                    PdfPKCS7 pkcs = acroFields.verifySignature(name);
                    signaturesByName.put(name, pkcs);
                }

                if (names == null || names.isEmpty()) {
                    // complianceCheck.addWarning("Il PDF non contiene firme");
                    signed = false;
                } else {
                    signed = true;
                }
            } catch (IOException e) {
                signed = false;
            } finally {
                if (reader != null) {
                    reader.close();
                }
            }

        } catch (Exception e) {
            signed = false;
        }
        return signed;
    }

    private boolean isSignedType(InputStream stream, ValidationInfos complianceCheck) {
        // Resetto il signer
        reset();
        acroFields = null;
        signaturesByName = null;

        boolean signed = false;
        PdfReader reader;
        signaturesByName = new HashMap<String, PdfPKCS7>();
        try {
            reader = new PdfReader(stream);
            acroFields = reader.getAcroFields();
            ArrayList<String> names = acroFields.getSignatureNames();
            for (String name : names) {
                PdfPKCS7 pkcs = acroFields.verifySignature(name);
                signaturesByName.put(name, pkcs);
            }

            if (names == null || names.isEmpty()) {
                // complianceCheck.addWarning("Il PDF non contiene firme");
                signed = false;
            } else {
                signed = true;
            }
        } catch (IOException e) {
            signed = false;
        }
        return signed;
    }

    /**
     * Verifica la presenza di campi acrobat contenenti firme pkcs7
     */
    public boolean isSignedType(byte[] content, ValidationInfos complianceCheck) {
        ByteArrayInputStream stream = null;
        try {
            stream = new ByteArrayInputStream(content);
            return isSignedType(stream, complianceCheck);
        } finally {
            if (stream != null) {
                IOUtils.closeQuietly(stream);
            }
        }
    }

    public TimeStampToken[] getTimeStampTokens() {
        if (timestamptokens == null) {
            ArrayList<TimeStampToken> timestamptokenList = new ArrayList<TimeStampToken>();
            try {
                ArrayList<String> names = acroFields.getSignatureNames();
                String name;
                for (Iterator<String> it = names.iterator(); it.hasNext();) {
                    name = it.next();
                    PdfPKCS7 pkcs = acroFields.verifySignature(name);
                    if (pkcs.getTimeStampToken() != null) {
                        timestamptokenList.add(pkcs.getTimeStampToken());
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
            return timestamptokenList.toArray(new TimeStampToken[timestamptokenList.size()]);
        } else {
            return timestamptokens;
        }
    }

    public SignerType getFormat() {
        return SignerType.PADES;
    }

    @Override
    public ValidationInfos validateTimeStampTokensEmbedded() {
        ValidationInfos validationInfos = new ValidationInfos();
        if (this.signaturesByName == null) {
            if (!this.isSignedType(file, validationInfos)) {
                validationInfos.addError("File non in formato: " + this.getFormat());
                validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
                return validationInfos;
            } else {
                getTimeStampTokens();
            }
        }
        Set<String> signatureNames = signaturesByName.keySet();
        for (String signatureName : signatureNames) {
            try {
                PdfPKCS7 signature = signaturesByName.get(signatureName);
                if (!signature.verifyTimestampImprint()) {
                    validationInfos
                            .addError("La marca temporale associata alla firma: " + signatureName + " non è valido");
                    validationInfos.setEsito(EsitoControllo.NEGATIVO);
                }
            } catch (NoSuchAlgorithmException e) {
                validationInfos.addError("Impossibile validare la marca temporale assocuata alla firma: "
                        + signatureName + " spoichè l'algoritmo di hashing non è supportato");
                validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
            }
        }
        return validationInfos;
    }

    @Override
    public ValidationInfos validateTimeStampTokensEmbedded(TimeStampToken timeStampToken) {
        ValidationInfos validationInfos = new ValidationInfos();
        if (this.signaturesByName == null) {
            if (!this.isSignedType(file, validationInfos)) {
                validationInfos.addError("File non in formato: " + this.getFormat());
                validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
                return validationInfos;
            } else {
                getTimeStampTokens();
            }
        }
        Set<String> signatureNames = signaturesByName.keySet();
        for (String signatureName : signatureNames) {
            try {
                PdfPKCS7 signature = signaturesByName.get(signatureName);
                TimeStampToken sigTst = signature.getTimeStampToken();
                // Se il timestamp in input è quello riferito alla firma corrente effettuo il controllo
                if (sigTst != null && sigTst.equals(timeStampToken)) {
                    if (!signature.verifyTimestampImprint()) {
                        validationInfos.addError(
                                "La marca temporale associata alla firma: " + signatureName + " non è valido");
                        validationInfos.setEsito(EsitoControllo.NEGATIVO);
                    }
                    break;
                }
            } catch (NoSuchAlgorithmException e) {
                validationInfos.addError("Impossibile validare la marca temporale assocuata alla firma: "
                        + signatureName + " spoichè l'algoritmo di hashing non è supportato");
                validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
            }
        }
        return validationInfos;
    }

    public List<ISignature> getSignatures() {
        if (signaturesByName == null) {
            if (!this.isSignedType(file, new ValidationInfos())) {
                return null;
            }
        }
        List<ISignature> pdfSignatures = new ArrayList<ISignature>();
        for (String name : signaturesByName.keySet()) {
            PdfPKCS7 signature = signaturesByName.get(name);
            PdfDictionary pdfD = acroFields.getSignatureDictionary(name);
            PdfString string = (PdfString) pdfD.get(PdfName.CONTENTS);
            byte[] encoded = string.getOriginalBytes();
            CMSSignedData cms = null;
            byte[] signatureBytes = null;
            PdfName sub = pdfD.getAsName(PdfName.SUBFILTER);
            try {
                if (sub.equals(PdfName.ADBE_X509_RSA_SHA1)) {
                    ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(encoded));
                    signatureBytes = ((DEROctetString) in.readObject()).getOctets();
                    PDFSignature pdfSignature = new PDFSignature(signature, signatureBytes, SignerType.PDF_DSIG);
                    pdfSignatures.add(pdfSignature);
                } else {
                    cms = new CMSSignedData(encoded);
                    signatureBytes = ((List<SignerInformation>) cms.getSignerInfos().getSigners()).get(0)
                            .getSignature();
                    PDFSignature pdfSignature = new PDFSignature(signature, signatureBytes, P7MSigner.getType(
                            ((List<SignerInformation>) cms.getSignerInfos().getSigners()).get(0), true, false));
                    pdfSignatures.add(pdfSignature);
                }
            } catch (IOException ex) {
                log.error("Impossibile ottenere i byte della firma ADBE_X509_RSA_SHA1 dal PDF", ex);
            } catch (CMSException ex) {
                log.error("Impossibile costruire la busta CMS dalla firma PDF", ex);
            }

        }
        return pdfSignatures;
    }

    /*
     * TODO!!
     */
    public byte[] getUnsignedContentDigest(MessageDigest digestAlgorithm) {
        return null;
    }

    /*
     * TODO!!
     */
    public InputStream getUnsignedContent() {
        // TODO Auto-generated method stub
        return null;
    }

    public boolean canContentBeSigned() {
        return false;
    }

    public Collection<CRL> getEmbeddedCRLs() {
        // TODO Auto-generated method stub
        return null;
    }

    public Collection<? extends Certificate> getEmbeddedCertificates() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public SignerType getTimeStampFormat() {
        return SignerType.PADES;
    }
}
