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
import it.eng.crypto.data.type.SignerType;
import it.eng.crypto.exception.CryptoSignerException;
import it.eng.crypto.utils.VerificheEnums.EsitoControllo;

import java.io.*;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;

import javax.mail.MessagingException;
import org.apache.commons.codec.binary.Base64InputStream;
//import javax.mail.internet.MimeBodyPart;
//import javax.mail.internet.MimeMessage;
//import javax.mail.internet.MimeMultipart;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.james.mime4j.dom.*;
import org.apache.james.mime4j.message.BodyPart;
import org.apache.james.mime4j.message.DefaultMessageBuilder;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * Implementa i controlli su firme di tipo M7M. Il contenuto di un file è riconosciuto se implementa le specifiche
 * S/MIME
 *
 * @author Stefano Zennaro
 */
public class M7MSigner extends AbstractSigner {

    private BinaryBody p7mPart = null;
    protected CMSSignedData cmsSignedData = null;

    public TimeStampToken[] getTimeStampTokens() {
        if (timestamptokens == null) {
            TimeStampResponse resp = null;
            TimeStampToken tsToken = null;
            InputStream stream = null;
            try {
                stream = FileUtils.openInputStream(getFile());
                MessageBuilder build = new DefaultMessageBuilder();
                Message mimeMsg = build.parseMessage(stream);
                if (mimeMsg.isMultipart()) {
                    Multipart multipart = (Multipart) mimeMsg.getBody();
                    for (Entity en : multipart.getBodyParts()) {
                        BodyPart part = (BodyPart) en;
                        if (part.isMimeType("application/timestamp-reply")
                                || part.isMimeType("application/timestamp")) {
                            byte[] buffer = null;
                            byte[] input = IOUtils.toByteArray(((BinaryBody) part.getBody()).getInputStream());
                            try {
                                resp = new TimeStampResponse(input);
                                tsToken = resp.getTimeStampToken();
                            } catch (Exception e1) {
                                try {
                                    org.bouncycastle.util.encoders.Base64 dec = new org.bouncycastle.util.encoders.Base64();
                                    buffer = dec.decode(input);
                                    resp = new TimeStampResponse(buffer);
                                    tsToken = resp.getTimeStampToken();
                                } catch (Exception e) {
                                    try {
                                        tsToken = new TimeStampToken(new CMSSignedData(input));
                                    } catch (Exception er) {
                                        throw new CryptoSignerException("Formato token non riconosciuto", e);
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                log.error("Eccezione generica", e);
                tsToken = null;
            } finally {
                if (stream != null) {
                    IOUtils.closeQuietly(stream);
                }
            }

            return timestamptokens = new TimeStampToken[] { tsToken };
        } else {
            return timestamptokens;
        }
    }

    private BodyPart getP7MPart() {
        InputStream stream = null;
        try {
            stream = FileUtils.openInputStream(getFile());
            MessageBuilder build = new DefaultMessageBuilder();
            Message mimeMsg = build.parseMessage(stream);
            if (mimeMsg.isMultipart()) {
                Multipart multipart = (Multipart) mimeMsg.getBody();
                for (Entity e : multipart.getBodyParts()) {
                    BodyPart part = (BodyPart) e;
                    if (part.isMimeType("application/pkcs7-mime")) {
                        return part;
                    }
                }
            }
        } catch (Exception e) {
            if (stream != null) {
                IOUtils.closeQuietly(stream);
            }
        } finally {
            if (stream != null) {
                IOUtils.closeQuietly(stream);
            }
        }
        return null;
    }

    public boolean isSignedType(File file, ValidationInfos complianceCheck) {
        if (file == null) {
            return false;
        }
        InputStream stream = null;
        try {
            stream = FileUtils.openInputStream(file);
            int streamLength = (file.length() > (long) Integer.MAX_VALUE) ? Integer.MAX_VALUE : (int) file.length();
            return isSignedType(stream, streamLength, complianceCheck);
        } catch (IOException e) {
            return false;
        } finally {
            if (stream != null) {
                IOUtils.closeQuietly(stream);
            }
        }
    }

    private boolean isSignedType(InputStream stream, int streamLength, ValidationInfos complianceCheck) {
        // Resetto il signer
        reset();
        p7mPart = null;

        boolean ism7m = false;
        boolean timestamp_reply = false;
        boolean pcks7_mime = false;
        try {

            DefaultMessageBuilder build = new DefaultMessageBuilder();
            // Fondamentale, altrimenti il parsing provvedera a decodificare eventuali parti in base64: se in una parte
            // è presente un PEM verrebbe decodificata anche l'intestazione (------BEGIN ..) producendo una decodifica
            // errata
            build.setContentDecoding(false);
            Message mimeMsg = build.parseMessage(stream);
            if (mimeMsg.isMultipart()) {
                Multipart multipart = (Multipart) mimeMsg.getBody();
                for (Entity e : multipart.getBodyParts()) {
                    BodyPart part = (BodyPart) e;
                    if (part.isMimeType("application/timestamp-reply") || part.isMimeType("application/timestamp")) {
                        if (timestamp_reply) {
                            // se ci sono due marche non è un M7M
                            return false;
                        }
                        timestamp_reply = true;
                    } else if (part.isMimeType("application/pkcs7-mime")) {
                        if (pcks7_mime) {
                            // se ci sono due firme non è un M7M
                            return false;
                        }
                        pcks7_mime = true;
                        p7mPart = (BinaryBody) part.getBody();
                    }
                }
            } else {
                return false;
            }

        } catch (Exception e) {
            ism7m = false;
        }
        if (timestamp_reply && pcks7_mime) {
            ism7m = true;
            InputStream partStream = null;

            try {
                partStream = p7mPart.getInputStream();
                PEMReader pr = null;
                try {
                    partStream = p7mPart.getInputStream();
                    pr = new PEMReader(new InputStreamReader(partStream));
                    Object obj = pr.readObject();
                    if (obj instanceof ContentInfo) {
                        ContentInfo ci = (ContentInfo) obj;
                        if (ci != null) {
                            cmsSignedData = new CMSSignedData(ci);
                        }
                    }
                } catch (IOException ex) {
                } finally {
                    if (pr != null) {
                        IOUtils.closeQuietly(pr);
                    }
                }
                if (cmsSignedData == null) {
                    partStream = p7mPart.getInputStream();
                    ContentInfo ci = ContentInfo.getInstance(
                            new ASN1InputStream(new BufferedInputStream(partStream), streamLength).readObject());
                    cmsSignedData = new CMSSignedData(ci);
                }
            } catch (Exception e) {
                try {
                    if (partStream != null) {
                        IOUtils.closeQuietly(partStream);
                    }
                    partStream = p7mPart.getInputStream();
                    ContentInfo ci = ContentInfo.getInstance(
                            new ASN1InputStream(new Base64InputStream(partStream), streamLength).readObject());
                    cmsSignedData = new CMSSignedData(ci);
                } catch (Exception e2) {
                    complianceCheck.addWarning("Il file M7M contiene una busta CMS non valida o corrotta");
                    return false;
                }

            } finally {
                if (partStream != null) {
                    IOUtils.closeQuietly(partStream);
                }
            }
        }
        return ism7m;

    }

    /**
     * Restituisce true se il contenuto è di tipo S/MIME e contiene le seguenti parti:
     * <ul>
     * <li>application/timestamp-reply</li>
     * <li>application/pkcs7-mime</li>
     * </ul>
     */
    public boolean isSignedType(byte[] content, ValidationInfos complianceCheck) {
        ByteArrayInputStream bais = null;
        try {
            bais = new ByteArrayInputStream(content);
            return isSignedType(bais, content.length, complianceCheck);
        } finally {
            if (bais != null) {
                IOUtils.closeQuietly(bais);
            }
        }
    }

    public SignerType getFormat() {
        return SignerType.M7M;
    }

    public ValidationInfos validateTimeStampTokensEmbedded() {
        ValidationInfos validationInfos = new ValidationInfos();
        if (this.file == null) {
            validationInfos.addError("File di non specificato");
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
            return validationInfos;
        }
        if (this.timestamptokens == null) {
            getTimeStampTokens();
        }
        // validationInfos.setValidatedObject(timestamptoken);
        try {
            if (timestamptokens == null) {
                throw new Exception();
            }
            for (TimeStampToken timestamptoken : timestamptokens) {
                TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
                String hashAlgOID = timestamptoken.getTimeStampInfo().getMessageImprintAlgOID();
                MessageDigest digest = MessageDigest.getInstance(hashAlgOID);
                TimeStampRequest request = gen.generate(hashAlgOID,
                        digest.digest(IOUtils.toByteArray(p7mPart.getInputStream())));

                this.checkTimeStampTokenOverRequest(validationInfos, timestamptoken, request);
            }
        } catch (MessagingException e) {
            validationInfos.addError("Impossibile trovare il file firmato");
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
        } catch (NoSuchAlgorithmException e) {
            validationInfos.addError("Impossibile trovare l'algoritmo di digest");
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
        } catch (Exception e) {
            validationInfos.addError("Il token non contiene una marca temporale valida");
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
        }

        return validationInfos;
    }

    @Override
    public ValidationInfos validateTimeStampTokensEmbedded(TimeStampToken timeStampToken) {
        ValidationInfos validationInfos = new ValidationInfos();

        if (this.file == null) {
            validationInfos.addError("File di non specificato");
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
            return validationInfos;
        }
        if (this.timestamptokens == null) {
            getTimeStampTokens();
        }
        try {
            if (timestamptokens == null) {
                throw new Exception();
            }

            TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
            String hashAlgOID = timeStampToken.getTimeStampInfo().getMessageImprintAlgOID();
            MessageDigest digest = MessageDigest.getInstance(hashAlgOID);
            TimeStampRequest request = gen.generate(hashAlgOID,
                    digest.digest(IOUtils.toByteArray(p7mPart.getInputStream())));

            this.checkTimeStampTokenOverRequest(validationInfos, timeStampToken, request);

        } catch (MessagingException e) {
            validationInfos.addError("Impossibile trovare il file firmato");
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
        } catch (NoSuchAlgorithmException e) {
            validationInfos.addError("Impossibile trovare l'algoritmo di digest");
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
        } catch (Exception e) {
            validationInfos.addError("Il token non contiene una marca temporale valida");
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
        }

        return validationInfos;
    }

    protected void writeExtractedContentToFile(CMSSignedData cmsSignedData) throws IOException, CMSException {
        alreadyExtractedFile = File.createTempFile("content-m7m-signer-", getEnclosedEnvelopeExtension());
        FileOutputStream fos = new FileOutputStream(alreadyExtractedFile);
        cmsSignedData.getSignedContent().write(fos);
        fos.close();
    }

    public InputStream getUnsignedContent() {
        File detachedFile = getDetachedFile();

        // Si tratta della firma di un file detached?
        // - in teoria possono esistere m7m detached..
        if (detachedFile != null) {
            try {
                return FileUtils.openInputStream(detachedFile);
            } catch (IOException e1) {
                return null;
            }
        }

        if (p7mPart == null) {
            p7mPart = (BinaryBody) getP7MPart().getBody();
        }
        try {
            // Object content = ((BinaryBody) p7mPart.getBody()).getInputStream();
            //
            // CMSSignedData sd = new CMSSignedData((InputStream) content);

            // TODO: modificato, da testare
            // return P7MSigner.getCMSSignedDataUnsignedContent(sd);
            writeExtractedContentToFile(cmsSignedData);
            // ((InputStream) content).close();
            return null;

        } catch (IOException e) {
            log.error("Eccezione IO", e);
        } catch (CMSException e) {
            log.error("Eccezione CMS", e);
        }
        return null;
    }

    public byte[] getUnsignedContentDigest(MessageDigest digestAlgorithm) {
        InputStream unsignedContent = this.getUnsignedContent();
        try {
            return digestAlgorithm.digest(IOUtils.toByteArray(unsignedContent));
        } catch (IOException e) {
            log.error("Errore IO", e);
        } finally {
            if (unsignedContent != null) {
                try {
                    unsignedContent.close();
                } catch (IOException e) {
                    log.error("Errore IO", e);
                }
            }
        }
        return null;
    }

    public List<ISignature> getSignatures() {
        Object content = null;
        try {
            // content = ((BinaryBody) p7mPart.getBody()).getInputStream();
            // if (content instanceof InputStream) {
            // CMSSignedData cmsSignedData = new CMSSignedData((InputStream) content);

            return P7MSigner.getISigneturesFromCMSSignedData(cmsSignedData, detachedFiles, SignerType.M7M, false,
                    false);
            // }
            // } catch (CMSException e) {
            // log.error("Il contenuto non è una busta CMS");
        } catch (Exception e) {
            log.error("Eccezione generica", e);
        } finally {
            try {
                if (content instanceof InputStream) {
                    ((InputStream) content).close();
                }

            } catch (IOException e) {
                log.error("Errore IO", e);
            }
        }
        return null;
    }

    public boolean canContentBeSigned() {
        return true;
    }

    public Collection<CRL> getEmbeddedCRLs() {
        Object content;
        try {
            // content = ((BinaryBody) p7mPart.getBody()).getInputStream();
            // if (content instanceof InputStream) {
            // CMSSignedData cmsSignedData = new CMSSignedData((InputStream) content);
            return P7MSigner.getCRLsFromCMSSignedData(cmsSignedData);
            // }
        } catch (Exception e) {
            log.error("Eccezione generica", e);
        }
        return null;
    }

    public Collection<? extends Certificate> getEmbeddedCertificates() {
        Object content;
        try {
            // content = ((BinaryBody) p7mPart.getBody()).getInputStream();
            // if (content instanceof InputStream) {
            // CMSSignedData cmsSignedData = new CMSSignedData((InputStream) content);
            return P7MSigner.getCertificatesFromCMSSignedData(cmsSignedData);
            // }
        } catch (Exception e) {
            log.error("Eccezione generica", e);
        }
        return null;
    }

    @Override
    public SignerType getTimeStampFormat() {
        return SignerType.M7M;
    }
}
