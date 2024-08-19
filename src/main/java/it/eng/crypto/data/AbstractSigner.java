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
import it.eng.crypto.utils.VerificheEnums.EsitoControllo;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.StringTokenizer;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Classe di base per l'esecuzione delle operazioni di estrazione, analisi e validazione di firme digitali.
 *
 * Fornisce già i metodi per il controllo della corrispondenza tra marche temporali e contenuto firmato
 * ({@link checkTimeStampTokenOverRequest}) e l'estrazione del contenuto della busta su file ({@link getContentAsFile}).
 * I metodi astratti da implementare sono i seguenti:
 * <ul>
 * <li>isSignedType: effettua l'istanziazione delle strutture di supporto e restituisce true se il file analizzato è
 * riconosciuto</li>
 * <li>getFormat: restituisce il formato della busta nel caso sia stato riconosciuto</li>
 * <li>getTimeStampTokens: recupera le marche temporali contenute</li>
 * <li>getUnsignedContent: restituisce il contenuto sbustato</li>
 * <li>canContentBeSigned: restituisce true se il contenuto sbustato può a sua volta essere firmato (nel caso di firme
 * multiple esterne)</li>
 * <li>getSignatures: recupera le firme contenute all'interno della busta. Ciascuna firma appartiene ad una classe che
 * implementa l'interfaccia ISignature: contiene al suo interno la lista delle eventuali controfirme e il metodo di
 * validazione (sia sul contenuto embedded che su file detached - qualora previsto ).</li>
 * <li>validateTimeStampTokensEmbedded / validateTimeStampTokensDetached: implementano le validazioni delle marche
 * temporali interne o detached</li>
 * </ul>
 * Una classe estendente inoltre deve sovrascrivere uno dei metodi: {@link validateTimeStampTokensEmbedded} o
 * {@link validateTimeStampTokensDetached} a seconda se il conenuto firmato sia all'interno della busta o esterno.
 *
 * @author Stefano Zennaro
 *
 */
public abstract class AbstractSigner {

    /*
     * CAMPI
     */
    Logger log = LoggerFactory.getLogger(AbstractSigner.class);
    /**
     * File di firma con/senza contenuto
     */
    protected File file;
    /**
     * Contenuto detached
     */
    protected List<File> detachedFiles;
    /**
     * File precedentemente sbustato
     */
    protected File alreadyExtractedFile;
    /**
     * Marche temporali contenute nella busta
     */
    protected TimeStampToken[] timestamptokens = null;
    /**
     * Dimensione in byte oltre la quale effettuare una gestione NON in memoria (ie. in streaming) del file Default:
     * 20MB
     */
    protected long sizeThreshold = 1024 * 1024 * 20;

    /*
     * METODI ASTRATTI (da implementare nelle sottoclassi)
     */
    /**
     * Recupera il formato della busta nel caso sia stato riconosciuto
     *
     * @return
     */
    public abstract SignerType getFormat();

    /**
     * Recupera il formato dell'eventuale marca embedded
     *
     * @return
     */
    public abstract SignerType getTimeStampFormat();

    /**
     * Controlla se il file contiene firme in formato riconosciuto
     *
     * @param file
     *
     * @return true se il vi sono firme con formato riconosciuto
     */
    public abstract boolean isSignedType(File file, ValidationInfos complianceCheck);

    /**
     * Controlla se il contenuto in ingresso contiene firme
     *
     * @param content
     *            contenuto su cui eseguire il controllo
     *
     * @return true se il vi sono firme con formato riconosciuto
     */
    public abstract boolean isSignedType(byte[] content, ValidationInfos complianceCheck);

    /**
     * Ritorna il timestamptoken se presente. Se il token non esiste ritorna null.
     *
     * @return
     */
    public abstract TimeStampToken[] getTimeStampTokens();

    public void reset() {
        timestamptokens = null;
    }

    /**
     * Ritorna il contenuto non firmato
     *
     * @return
     */
    public abstract InputStream getUnsignedContent();

    /**
     * Restituisce true se il contenuto sbustato può a sua volta essere firmato (nel caso di firme multiple esterne)
     *
     * @return
     */
    public abstract boolean canContentBeSigned();

    /*
     * FIXME: da rimuovere, probabilmente è superfluo..
     */
    /**
     * Recupera l'hash del contenuto utilizzando l'algorimo di digest passato in ingresso - ogni firma presente può
     * utilizzare un proprio algoritmo di digest
     */
    public abstract byte[] getUnsignedContentDigest(MessageDigest digestAlgorithm);

    /**
     * Recupera le firme apposte
     */
    public abstract List<ISignature> getSignatures();

    /**
     * Recupera le CRL incluse all'interno del file firmato (solo per i formati di firma che lo prevedono)
     */
    public abstract Collection<CRL> getEmbeddedCRLs();

    /**
     * Recupera i certificati inclusi all'interno del file firmato (solo per i formati di firma che lo prevedono)
     */
    public abstract Collection<? extends Certificate> getEmbeddedCertificates();
    /*
     * METODI PUBBLICI
     */

    /**
     * Recupera il file di firma
     */
    public File getFile() {
        return file;
    }

    /**
     * Definisce il file di firma
     *
     * @param file
     */
    public void setFile(File file) {
        this.file = file;
        this.alreadyExtractedFile = null;
    }

    /**
     * Esegue la validazione di marche temporali embedded
     *
     * @return le informazioni sull'esito della validazione
     */
    public ValidationInfos validateTimeStampTokensEmbedded() {
        return null;
    }

    /**
     * Esegue la validazione di marche temporali embedded
     *
     * @return le informazioni sull'esito della validazione
     */
    public ValidationInfos validateTimeStampTokensEmbedded(TimeStampToken timeStampToken) {
        return null;
    }

    /**
     * Esegue la validazione di marche temporali detached
     *
     * @return le informazioni sull'esito della validazione
     */
    public ValidationInfos validateTimeStampTokensDetached(File attachedFile) {
        return null;
    }

    /**
     * Metodo di utilità che esegue la validazione di un timestamptoken rispetto al messaggio di request contenente
     * l'hashmap del contenuto da marcare.
     *
     * @param validationInfos
     *            struttura che raccoglie le informazioni riguardo all'esito della validazione del timestamp
     * @param timestamptoken
     *            token contenente la marca temporale
     * @param request
     *            classe contenente l'implementazione della richiesta di emissione di una marca temporale, secondo le
     *            specifiche descritte in RFC3161
     */
    protected void checkTimeStampTokenOverRequest(ValidationInfos validationInfos, TimeStampToken timestamptoken,
            TimeStampRequest request) {
        ASN1InputStream aIn = null;
        try {

            PKIStatusInfo paramPKIStatusInfo = new PKIStatusInfo(0);

            aIn = new ASN1InputStream(timestamptoken.getEncoded());
            ASN1Sequence seq = (ASN1Sequence) aIn.readObject();
            ContentInfo paramContentInfo = new ContentInfo(seq);
            TimeStampResp tsr = new TimeStampResp(paramPKIStatusInfo, paramContentInfo);
            TimeStampResponse response = new TimeStampResponse(tsr);

            checkTimeStampRequestOverTimeStampResponse(validationInfos, timestamptoken, request, response);

        } catch (IOException e) {
            validationInfos.addError("Il token non contiene una marca temporale valida");
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
        } catch (TSPException e) {
            validationInfos.addError(e.getMessage());
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
        } finally {
            IOUtils.closeQuietly(aIn);
        }
    }

    private void checkTimeStampRequestOverTimeStampResponse(ValidationInfos validationInfos,
            TimeStampToken timestamptoken, TimeStampRequest request, TimeStampResponse response) {

        String digestAlgorithmOID = null;

        /*
         * Verifica che la marca temporale sia effettivamente associata alla request
         */
        try {
            response.validate(request);
        } catch (TSPException e) {
            validationInfos.addError(e.getMessage());
            validationInfos.setEsito(EsitoControllo.NEGATIVO);
        }

        /*
         * Occorre quindi verificare che il timestamp sia stato effettivamente calcolato a partire dall'impronta del
         * file in ingresso, cioè: SignerInfo.digestAlgorithm(ContentInfo.Content / ContentInfo.signedAttributes) =
         * SignerInfo.signaturealgorithm^-1(SignerInfo.cid.publickey, SignerInfo.Signature)
         */
        try {

            CMSSignedData cms = timestamptoken.toCMSSignedData();
            CertStore certStore = timestamptoken.getCertificatesAndCRLs("Collection", "BC");

            Collection<Certificate> saCertificates = (Collection<Certificate>) certStore.getCertificates(null);
            if (saCertificates == null) {
                throw new Exception("Il certificato di TSA non risulta presente");
            }

            Certificate certificate = saCertificates.iterator().next();
            if (certificate == null) {
                throw new Exception("Il certificato di TSA non risulta presente");
            }
            PublicKey publicKey = certificate.getPublicKey();
            if (publicKey == null) {
                throw new Exception("La publicKey della TSA non risulta presente");
            }

            Collection<SignerInformation> signers = (Collection<SignerInformation>) cms.getSignerInfos().getSigners();
            SignerInformation signerInfo = signers.iterator().next();
            digestAlgorithmOID = signerInfo.getDigestAlgOID();
            MessageDigest contentDigestAlgorithm = MessageDigest.getInstance(digestAlgorithmOID);

            /*
             * I due byte array da verificare
             */
            byte[] encodedDataToVerify = null;
            byte[] encodedSignedData = null;

            /*
             * Verifica che il certificato sia corretto ripetto al firmatario - la public key è correttamente associata
             * al contenuto firmato
             */
            boolean certificateVerified = false;
            if (signerInfo.verify(publicKey, "BC")) {
                certificateVerified = true;
            }
            CMSProcessable signedContent = cms.getSignedContent();
            byte[] originalContent = (byte[]) signedContent.getContent();

            log.debug("originalContent.length: " + originalContent.length + " originalContent: "
                    + SignerUtil.asHex(originalContent));

            /*
             * Controllo se occorre calcolare il digest dell'eContent oppure degli attributi firmati
             */
            byte[] encodedSignedAttributes = signerInfo.getEncodedSignedAttributes();
            if (encodedSignedAttributes != null) {
                encodedDataToVerify = contentDigestAlgorithm.digest(encodedSignedAttributes);
            } else {
                encodedDataToVerify = contentDigestAlgorithm.digest((byte[]) cms.getSignedContent().getContent());
            }

            log.debug("encodedDataToVerify: " + SignerUtil.asHex(encodedDataToVerify));

            // Hash dell'econtent (da confrontare con l'hash del TSTInfo)
            byte[] contentDigest = signerInfo.getContentDigest();
            /*
             * FIXME: tstInfo.getEncoded() è stato sostituito con getSignedContent().getContent() poichè nelle m7m la
             * chiamata restituisce un errore - occorre verificare che i due metodi restituiscano lo stesso oggetto
             * (attualmente la mancata verifica viene segnalata solo come warning)
             */
            // TSTInfo tstInfo = timestamptoken.getTimeStampInfo().toTSTInfo();
            // byte[] tstInfoEncoded = contentDigestAlgorithm.digest(tstInfo.getEncoded());
            byte[] tstInfoEncoded = contentDigestAlgorithm.digest((byte[]) cms.getSignedContent().getContent());
            boolean contentVerified = Arrays.constantTimeAreEqual(contentDigest, tstInfoEncoded);

            digestAlgorithmOID = signerInfo.getEncryptionAlgOID();
            byte[] signature = signerInfo.getSignature();
            Cipher cipher = null;
            try {
                String algorithmName = null;
                if (PKCSObjectIdentifiers.rsaEncryption.getId().equals(digestAlgorithmOID)) {
                    algorithmName = "RSA/ECB/PKCS1Padding";
                } else if (PKCSObjectIdentifiers.sha1WithRSAEncryption.getId().equals(digestAlgorithmOID)) {
                    algorithmName = "RSA/ECB/PKCS1Padding";
                } else {
                    algorithmName = digestAlgorithmOID;
                }
                cipher = Cipher.getInstance(algorithmName, "BC");
            } catch (NoSuchPaddingException e1) {
            }
            if (cipher == null) {
                validationInfos.addWarning(
                        "Non è stato possibile verificare la corretta associazione tra marca temporale e file poichè l'algoritmo di firma non è supportato: "
                                + digestAlgorithmOID);
                validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
            } else {
                ASN1InputStream asn1is = null;
                try {
                    log.debug("Cipher: " + cipher.getAlgorithm());
                    cipher.init(Cipher.DECRYPT_MODE, publicKey);
                    byte[] decryptedSignature = cipher.doFinal(signature);

                    asn1is = new ASN1InputStream(decryptedSignature);
                    ASN1Sequence asn1Seq = (ASN1Sequence) asn1is.readObject();

                    Enumeration<? extends DERObject> objs = asn1Seq.getObjects();
                    while (objs.hasMoreElements()) {
                        DERObject derObject = objs.nextElement();
                        if (derObject instanceof ASN1OctetString) {
                            ASN1OctetString octectString = (ASN1OctetString) derObject;
                            encodedSignedData = octectString.getOctets();
                            break;
                        }
                    }
                    log.debug("encodedSignedData: " + SignerUtil.asHex(encodedSignedData));
                    boolean signatureVerified = Arrays.constantTimeAreEqual(encodedSignedData, encodedDataToVerify);

                    log.debug("Verifica timestampToken: certificateVerified = " + certificateVerified
                            + ", signatureVerified=" + signatureVerified + ", contentVerified=" + contentVerified);
                    if (!certificateVerified) {
                        validationInfos.addError("Il certificato non è valido");
                        validationInfos.setEsito(EsitoControllo.NEGATIVO);
                    }
                    if (!signatureVerified) {
                        validationInfos.addError("La firma non è valida: l'hash di contenuto + attributi è "
                                + SignerUtil.asHex(encodedDataToVerify)
                                + ", mentre la firma è stata apposta su contenuto + attributi con hash: "
                                + SignerUtil.asHex(encodedSignedData));
                        validationInfos.setEsito(EsitoControllo.NEGATIVO);
                    }
                    if (!contentVerified) {
                        validationInfos.addWarning("Il contenuto non corrisponde a quanto firmato: previsto "
                                + SignerUtil.asHex(tstInfoEncoded) + ", trovato " + SignerUtil.asHex(contentDigest));
                        validationInfos.setEsito(EsitoControllo.NEGATIVO);
                    }
                } catch (Exception e) {
                    validationInfos.addWarning("Errore durante la verifica del timestamp: " + e.getMessage());
                    validationInfos.setEsito(EsitoControllo.NEGATIVO);
                } finally {
                    IOUtils.closeQuietly(asn1is);
                }

            }
        } catch (IOException e) {
            validationInfos.addError("Il token non contiene una marca temporale valida");
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
        } catch (NoSuchAlgorithmException e) {
            validationInfos.addError("Impossibile validare la marca poichè l'algoritmo di hashing non è supportato: "
                    + digestAlgorithmOID);
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
        } catch (Exception e) {
            validationInfos.addError("Errore durante la validazione della marca temporale: " + e.getMessage());
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
        }
    }

    /**
     * Recupera il contenuto sbustato sotto forma di file.
     *
     *
     * @return restituisce il file originario se si tratta di marche detached, altrimenti salva il contenuto sbustato in
     *         un file temporaneo e ne restituisce il riferimento
     *
     * @throws IOException
     */
    public File getContentAsFile() throws IOException {

        // Se si tratta di una firma detached restituisco
        // il file a cui si riferisce
        File detachedFile = getDetachedFile();
        if (detachedFile != null) {
            return detachedFile;
        }

        // Se è già stato estratto il contenuto
        // restituisco il file corrispondente
        if (alreadyExtractedFile != null && alreadyExtractedFile.exists()) {
            return alreadyExtractedFile;
        }

        // Altrimenti occorre estrarre il contenuto..
        // Verifico se il nome del file contiene più estensioni
        // (ovvero estensione iniziale + firme: test.doc.p7m)
        // per preservare l'estensione originaria
        String extension = getEnclosedEnvelopeExtension();
        InputStream contentIS = null;
        OutputStream out = null;
        try {
            contentIS = getUnsignedContent();
            if (contentIS == null) {
                if (alreadyExtractedFile != null && alreadyExtractedFile.exists()) {
                    return alreadyExtractedFile;
                } else {
                    return null;
                }
            }
            alreadyExtractedFile = File.createTempFile("content-abstract-signer-", extension);
            out = new FileOutputStream(alreadyExtractedFile);
            byte buf[] = new byte[1024];
            int len;
            while ((len = contentIS.read(buf)) > 0) {
                out.write(buf, 0, len);
            }

        } catch (IOException ex) {
            throw ex;
        } finally {
            if (out != null) {
                out.close();
            }
            if (contentIS != null) {
                contentIS.close();
            }
        }
        return alreadyExtractedFile;

    }

    public String getEnclosedEnvelopeExtension() {
        if (file == null) {
            return null;
        }
        String fileName = getFile().getName();
        String extension = null;
        StringTokenizer tokenizer = new StringTokenizer(fileName, ".");
        if (tokenizer.countTokens() > 2) {
            tokenizer.nextToken();
            extension = "." + tokenizer.nextToken();
        }
        return extension;
    }

    /**
     * Definisce il file detached a cui si riferiscono le marche temporali
     */
    public void setDetachedFile(File detachedFile) {
        if (detachedFiles == null) {
            detachedFiles = new ArrayList<File>();
        }
        detachedFiles.add(0, detachedFile);
    }

    /**
     * Recupera il file detached a cui si riferiscono le marche temporali
     *
     * @return
     */
    public File getDetachedFile() {
        return detachedFiles == null ? null : detachedFiles.get(0);
    }

    public long getSizeThreshold() {
        return sizeThreshold;
    }

    public void setSizeThreshold(long sizeThreshold) {
        this.sizeThreshold = sizeThreshold;
    }

    protected CMSSignedData getSignedData(File file) throws IOException {
        InputStream stream = null;
        CMSSignedData cmsSignedData = null;
        PEMReader pr = null;
        try {
            pr = new PEMReader(new FileReader(file));
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
        int streamLength = (file.length() > (long) Integer.MAX_VALUE) ? Integer.MAX_VALUE : (int) file.length();
        if (cmsSignedData == null) {
            log.debug("Il file non è in formato PEM");
            try {
                stream = FileUtils.openInputStream(file);
                // Utilizzo il costruttore di CMSSignedData che accetta il ContentInfo così posso impostare il limite
                // superiore alla dimensione del file
                // al posto di: cmsSignedData = new CMSSignedData(new BufferedInputStream(stream));
                ContentInfo ci = ContentInfo
                        .getInstance(new ASN1InputStream(new BufferedInputStream(stream), streamLength).readObject());
                cmsSignedData = new CMSSignedData(ci);
            } catch (Exception e) {
                if (stream != null) {
                    IOUtils.closeQuietly(stream);
                }
                log.debug("Il file non è in formato DER");
                stream = FileUtils.openInputStream(file);
                // Utilizzo il costruttore di CMSSignedData che accetta il ContentInfo così posso impostare il limite
                // superiore alla dimensione del file
                // al posto di: cmsSignedData = new CMSSignedData(new Base64InputStream(stream));
                ContentInfo ci = ContentInfo
                        .getInstance(new ASN1InputStream(new Base64InputStream(stream), streamLength).readObject());
                cmsSignedData = new CMSSignedData(ci);
            } finally {
                if (stream != null) {
                    IOUtils.closeQuietly(stream);
                }
            }
        }
        return cmsSignedData;

    }
}
