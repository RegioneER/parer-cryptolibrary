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

/*
 * To change this template, choose Tools | Templates and open the template in the editor.
 */
package it.eng.crypto.data;

import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.data.signature.ISignature;
import it.eng.crypto.data.type.SignerType;
import it.eng.crypto.utils.VerificheEnums;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.cms.CMSTimeStampedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Quaranta_M
 */
public class TsdSigner extends AbstractSigner {

    private CMSTimeStampedData tsd;
    Logger log = LoggerFactory.getLogger(this.getClass().getName());

    @Override
    public SignerType getFormat() {
        return SignerType.TSD;
    }

    @Override
    public SignerType getTimeStampFormat() {
        return SignerType.TSD;
    }

    @Override
    public boolean isSignedType(File file, ValidationInfos complianceChecks) {
        InputStream stream = null;
        this.file = file;
        try {
            stream = FileUtils.openInputStream(file);
            int streamLength = (file.length() > (long) Integer.MAX_VALUE) ? Integer.MAX_VALUE
                    : (int) file.length();
            return isSignedType(stream, streamLength, complianceChecks);
        } catch (IOException e) {
            log.debug("Errore IO", e);
        } finally {
            if (stream != null) {
                IOUtils.closeQuietly(stream);
            }
        }
        return false;
    }

    public boolean isSignedType(InputStream stream, int streamLength,
            ValidationInfos complianceInfos) {
        boolean isTsd = false;
        try {

            tsd = new CMSTimeStampedData(ContentInfo
                    .getInstance(new ASN1InputStream(stream, streamLength).readObject()));
            timestamptokens = tsd.getTimeStampTokens();
            isTsd = true;
        } catch (Exception e) {
            log.debug("Errore generico", e);
        } finally {
            if (stream != null) {
                IOUtils.closeQuietly(stream);
            }
        }
        return isTsd;
    }

    @Override
    public boolean isSignedType(byte[] content, ValidationInfos complianceCheck) {
        throw new UnsupportedOperationException(
                "L'invocazione tramite byte array non è supportata");
    }

    @Override
    public TimeStampToken[] getTimeStampTokens() {
        if (timestamptokens == null) {
            isSignedType(file, new ValidationInfos());
        }
        return timestamptokens;
    }

    @Override
    public InputStream getUnsignedContent() {
        try {
            alreadyExtractedFile = File.createTempFile("content-tsd-signer",
                    getEnclosedEnvelopeExtension());
            if (tsd.getContent() != null) {
                FileUtils.writeByteArrayToFile(alreadyExtractedFile, tsd.getContent());
            }
        } catch (Exception e) {
            log.error("Errore IO", e);
        }
        return new ByteArrayInputStream(tsd.getContent());
    }

    @Override
    public boolean canContentBeSigned() {
        return true;
    }

    @Override
    public byte[] getUnsignedContentDigest(MessageDigest digestAlgorithm) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ISignature> getSignatures() {
        // Ritorna sempre null in quanto il file tsd non ha firme al suo interno. NB: è necessario
        // che .
        return null;
    }

    @Override
    public Collection<CRL> getEmbeddedCRLs() {
        return null;
    }

    @Override
    public Collection<? extends Certificate> getEmbeddedCertificates() {
        return null;
    }

    public ValidationInfos validateTimeStampTokensEmbedded() {
        ValidationInfos validationInfos = new ValidationInfos();
        if (this.timestamptokens == null) {
            if (!this.isSignedType(file, validationInfos)) {
                validationInfos.addError("File non in formato: " + this.getFormat());
                return validationInfos;
            }
        }
        return validationInfos;
    }

    public ValidationInfos validateTimeStampTokensEmbedded(TimeStampToken timeStampToken) {
        ValidationInfos validationInfos = new ValidationInfos();
        if (this.timestamptokens == null || this.timestamptokens.length == 0) {
            if (!this.isSignedType(file, validationInfos)) {
                validationInfos.addError("File non in formato: " + this.getFormat());
                validationInfos.setEsito(VerificheEnums.EsitoControllo.FORMATO_NON_CONOSCIUTO);
                return validationInfos;
            }
        }
        try {
            TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
            String hashAlgOID = timeStampToken.getTimeStampInfo().getMessageImprintAlgOID().getId();
            MessageDigest digest = MessageDigest.getInstance(hashAlgOID);
            TimeStampRequest request = gen.generate(hashAlgOID, digest.digest(tsd.getContent()));
            this.checkTimeStampTokenOverRequest(validationInfos, timeStampToken, request);
        } catch (Exception e) {
            validationInfos.addError(
                    "Errore durante la validazione della marca temporale: " + e.getMessage());
            validationInfos.setEsito(VerificheEnums.EsitoControllo.FORMATO_NON_CONOSCIUTO);
        }
        return validationInfos;
    }
}
