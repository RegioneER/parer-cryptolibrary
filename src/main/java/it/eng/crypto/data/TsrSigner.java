package it.eng.crypto.data;

import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.data.signature.ISignature;
import it.eng.crypto.data.type.SignerType;
import it.eng.crypto.utils.VerificheEnums.EsitoControllo;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;

import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * Implementa i controlli su firme di tipo CAdES. Il contenuto di un file è riconosciuto se implementa le specifiche
 * RFC3161
 *
 * @author Stefano Zennaro
 *
 */
public class TsrSigner extends AbstractSigner {

    CMSSignedData cmsSignedData = null;

    public TimeStampToken[] getTimeStampTokens() {
        if (timestamptokens == null) {
            isSignedType(file, new ValidationInfos());
        }
        return timestamptokens;
    }

    /**
     * Restituisce true se il contenuto del file contiene la codifica di un TimeStampResponse
     */
    public boolean isSignedType(File file, ValidationInfos complianceChecks) {
        if (file == null || file.length() > 1024 * 1024 * 1) {
            return false;
        }
        // byte[] buffer = null;
        InputStream stream = null;
        this.file = file;
        try {
            stream = FileUtils.openInputStream(file);
            int streamLength = (file.length() > (long) Integer.MAX_VALUE) ? Integer.MAX_VALUE : (int) file.length();
            return isSignedType(stream, streamLength, complianceChecks);
        } catch (IOException e) {
            log.error("Errore IO", e);
        } finally {
            if (stream != null) {
                IOUtils.closeQuietly(stream);
            }
        }
        return false;
    }

    /**
     * Restituisce true se il contenuto corrisponte alla codifica di un TimeStampResponse
     */
    @Override
    public boolean isSignedType(byte[] buffer, ValidationInfos complianceInfos) {
        TimeStampToken timestamptoken = null;
        boolean isTsr = false;
        InputStream stream = null;
        try {
            // buffer = FileUtils.readFileToByteArray(file);
            timestamptoken = new TimeStampResponse(buffer).getTimeStampToken();
            isTsr = true;
        } catch (Exception e1) {
            try {
                byte[] buffer64 = org.bouncycastle.util.encoders.Base64.decode(buffer);
                timestamptoken = new TimeStampResponse(buffer64).getTimeStampToken();
                isTsr = true;
            } catch (Exception e) {
                try {
                    timestamptoken = new TimeStampToken(cmsSignedData = new CMSSignedData(buffer));
                    isTsr = true;
                } catch (Exception e2) {
                    isTsr = false;
                }

            }
        } finally {
            if (stream != null) {
                IOUtils.closeQuietly(stream);
            }
        }
        if (timestamptoken != null) {
            timestamptokens = new TimeStampToken[] { timestamptoken };
        }
        return isTsr;
    }

    public boolean isSignedType(InputStream stream, int streamLength, ValidationInfos complianceInfos) {
        TimeStampToken timestamptoken = null;
        boolean isTsr = false;

        try {
            // Utilizzo il costruttore di ASN1InputStream passandogli come limite la dimensione del file; altrimenti
            // file diversi da una marca temporale potrebbero
            // causare OOM
            TimeStampResp tsr = TimeStampResp.getInstance(new ASN1InputStream(stream, streamLength).readObject());
            timestamptoken = new TimeStampResponse(tsr).getTimeStampToken();
            isTsr = true;
        } catch (Exception e1) {
            try {
                if (stream != null) {
                    IOUtils.closeQuietly(stream);
                }
                stream = FileUtils.openInputStream(file);
                Base64InputStream b64is = new Base64InputStream(stream);
                // Utilizzo il costruttore di ASN1InputStream passandogli come limite la dimensione del file; altrimenti
                // file diversi da una marca temporale potrebbero
                // causare OOM
                TimeStampResp tsr = TimeStampResp.getInstance(new ASN1InputStream(b64is, streamLength).readObject());
                timestamptoken = new TimeStampResponse(tsr).getTimeStampToken();
                isTsr = true;
            } catch (Exception e) {
                try {
                    if (stream != null) {
                        IOUtils.closeQuietly(stream);
                    }
                    stream = FileUtils.openInputStream(file);
                    ContentInfo ci = ContentInfo.getInstance(new ASN1InputStream(stream, streamLength).readObject());
                    cmsSignedData = new CMSSignedData(ci);
                    timestamptoken = new TimeStampToken(cmsSignedData);
                    isTsr = true;
                } catch (Exception e2) {
                    isTsr = false;
                }

            }
        } finally {
            if (stream != null) {
                IOUtils.closeQuietly(stream);
            }
        }
        if (timestamptoken != null) {
            timestamptokens = new TimeStampToken[] { timestamptoken };
        }
        return isTsr;
    }

    @Override
    public SignerType getFormat() {
        return SignerType.TSR;
    }

    @Override
    public ValidationInfos validateTimeStampTokensDetached(File attachedFile) {
        ValidationInfos validationInfos = new ValidationInfos();
        if (this.file == null) {
            validationInfos.addError("File di non specificato");
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
            return validationInfos;
        }
        if (this.timestamptokens == null || this.timestamptokens.length == 0) {
            if (!this.isSignedType(file, validationInfos)) {
                validationInfos.addError("File non in formato: " + this.getFormat());
                validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
                return validationInfos;
            } else {
                getTimeStampTokens();
            }
        }

        // validationInfos.setValidatedObject(timestamptoken);
        String hashAlgOID = null;
        try {
            if (timestamptokens == null) {
                throw new Exception("Il token non contiene una marca temporale");
            }
            for (TimeStampToken timestamptoken : timestamptokens) {
                TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
                hashAlgOID = timestamptoken.getTimeStampInfo().getMessageImprintAlgOID();
                MessageDigest digest = MessageDigest.getInstance(hashAlgOID);
                byte[] hash = generateHash(digest, validationInfos, attachedFile);
                TimeStampRequest request = gen.generate(hashAlgOID, hash);
                checkTimeStampTokenOverRequest(validationInfos, timestamptoken, request);
            }
        } catch (Exception e) {
            validationInfos.addError("Errore durante la validazione della marca temporale: " + e.getMessage());
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
        }
        return validationInfos;
    }

    private byte[] generateHash(MessageDigest digest, ValidationInfos validationInfos, File... files) {
        if (files == null) {
            return null;
        }
        for (File file : files) {
            try (FileInputStream fis = FileUtils.openInputStream(file)) {
                digest.update(IOUtils.toByteArray(fis));
            } catch (FileNotFoundException e) {
                validationInfos.addError("Il file su cui validare la marca temporale non e' stato trovato");
            } catch (IOException e) {
                validationInfos.addError("Il token non contiene una marca temporale valida");
            }
        }
        return digest.digest();
    }

    @Override
    public byte[] getUnsignedContentDigest(MessageDigest digestAlgorithm) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<ISignature> getSignatures() {
        if (timestamptokens == null || timestamptokens.length == 0) {
            return null;
        }
        TimeStampToken timestamptoken = timestamptokens[0];
        return P7MSigner.getISigneturesFromCMSSignedData(timestamptoken.toCMSSignedData(), null, SignerType.TSR, false,
                false);
    }

    public InputStream getUnsignedContent() {
        // TODO Auto-generated method stub
        return null;
    }

    public boolean canContentBeSigned() {
        return false;
    }

    public Collection<CRL> getEmbeddedCRLs() {
        return null;
    }

    public Collection<? extends Certificate> getEmbeddedCertificates() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public SignerType getTimeStampFormat() {
        return SignerType.TSR;
    }
}