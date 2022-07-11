package it.eng.crypto.data;

import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.data.signature.CMSSignature;
import it.eng.crypto.data.signature.ISignature;
import it.eng.crypto.data.type.SignerType;
import java.io.BufferedInputStream;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.logging.LogManager;

import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.x509.X509Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementa i controlli su firme di tipo P7M. Il contenuto di un file è riconosciuto se implementa le specifiche PKCS
 * #7
 *
 * @author Stefano Zennaro
 *
 */
public class P7MSigner extends AbstractSigner {

    /**
     * Contenuto CMS
     */
    protected CMSSignedData cmsSignedData = null;
    static Logger logger = LoggerFactory.getLogger(P7MSigner.class.getName());
    protected SignerType type = null;

    protected boolean isSignedType(CMSSignedData signedData, ValidationInfos complianceCheck) {
        // Resetto il signer
        reset();
        // cmsSignedData = null;

        boolean signed = false;
        SignerInformationStore signersStore = signedData.getSignerInfos();
        Collection<SignerInformation> signers = signersStore.getSigners();
        if (signers == null || signers.isEmpty()) {
            complianceCheck.addWarning("La busta CMS non contiene firme");
            signed = false;
        } else {
            // Controllo se l'algoritmo è di tipo SHA1
            for (SignerInformation signer : signers) {
                if (!CMSSignedDataGenerator.DIGEST_MD5.equals(signer.getDigestAlgOID())
                        && !CMSSignedDataGenerator.DIGEST_SHA1.equals(signer.getDigestAlgOID())
                        && !CMSSignedDataGenerator.DIGEST_SHA256.equals(signer.getDigestAlgOID())) {
                    signed = false;
                    complianceCheck.setWarnings(
                            new String[] { "Almeno una firma nella busta non utilizza MD5, SHA-1 o SHA-256" });
                    break;
                }
                signed = true;
            }
        }
        return signed;
    }

    /**
     * Restituisce true se il contenuto del file è di tipo CMS e l'algoritmo di digest è di tipo SHA1
     */
    @Override
    public boolean isSignedType(File file, ValidationInfos complianceCheck) {
        boolean signed = false;
        InputStream stream = null;
        // CMSProcessable process = new CMSProcessableFile(file);
        // byte[] out = (byte[]) process.getContent();

        PEMReader pr = null;

        try {
            pr = new PEMReader(new FileReader(file));
            ContentInfo ci = (ContentInfo) pr.readObject();
            if (ci != null) {
                cmsSignedData = new CMSSignedData(ci);
            }
        } catch (IOException ex) {
        } finally {
            if (pr != null) {
                IOUtils.closeQuietly(pr);
            }
        }
        try {
            if (cmsSignedData == null) {
                logger.debug("Il file non è in formato PEM");
                try {
                    stream = FileUtils.openInputStream(file);
                    cmsSignedData = new CMSSignedData(new BufferedInputStream(stream));
                } catch (CMSException e) {
                    if (stream != null) {
                        IOUtils.closeQuietly(stream);
                    }
                    logger.debug("Il file non è in formato DER");
                    stream = FileUtils.openInputStream(file);
                    cmsSignedData = new CMSSignedData(new Base64InputStream(stream));
                }

            }
            // CMSTypedStream cmsTypedStream = cmsSignedData.getSignedContent();
            // cmsTypedStream.drain();

            signed = isSignedType(cmsSignedData, complianceCheck);
        } catch (Exception e) {
            logger.debug("Il file non è in formato BASE64");
            signed = false;
        } finally {
            if (stream != null) {
                IOUtils.closeQuietly(stream);
            }
        }
        return signed;
    }

    @Override
    public boolean isSignedType(byte[] content, ValidationInfos complianceCheck) {
        boolean signed = false;
        try {
            cmsSignedData = new CMSSignedData(content);
            signed = isSignedType(cmsSignedData, complianceCheck);
        } catch (CMSException e) {
            signed = false;
        }
        return signed;
    }

    @Override
    public TimeStampToken[] getTimeStampTokens() {
        // Ritorna sempre null in quanto il file p7m non ha un TimeStampToken al suo interno.
        return null;
    }

    @Override
    public SignerType getFormat() {
        return SignerType.P7M;
    }

    /**
     * Ritorna il contenuto non firmato da una struttura di tipo CMSSigned
     */
    public static InputStream getCMSSignedDataUnsignedContent(CMSSignedData sd) {
        Object content = sd.getSignedContent().getContent();
        if (content instanceof byte[]) {
            // Recupero il contenuto della busta
            return new ByteArrayInputStream((byte[]) sd.getSignedContent().getContent());
        } else if (content instanceof InputStream) {
            return (InputStream) content;
        }
        return null;
    }

    protected void writeExtractedContentToFile() throws IOException, CMSException {
        alreadyExtractedFile = File.createTempFile("content-p7m-signer-", getEnclosedEnvelopeExtension());
        try (FileOutputStream fos = new FileOutputStream(alreadyExtractedFile)) {
            if (cmsSignedData.getSignedContent() != null) {
                cmsSignedData.getSignedContent().write(fos);
            }
        }
    }

    @Override
    public InputStream getUnsignedContent() {
        try (FileInputStream fis = FileUtils.openInputStream(file)) {
            File detachedFile = getDetachedFile();
            // Si tratta della firma di un file detached?
            if (detachedFile != null) {
                return FileUtils.openInputStream(detachedFile);
            } else {
                if (cmsSignedData == null) {
                    cmsSignedData = new CMSSignedData(fis);
                } else {
                    // TODO modificato (da testare)
                    // return getCMSSignedDataUnsignedContent(cmsSignedData);
                    writeExtractedContentToFile();
                    return null;
                }
            }
        } catch (Exception e) {
            logger.error("Eccezione generica", e);
        }
        return null;
    }

    @Override
    public byte[] getUnsignedContentDigest(MessageDigest digestAlgorithm) {
        InputStream unsignedContent = this.getUnsignedContent();
        byte[] buff = new byte[Byte.SIZE * 512];
        int length = -1;
        digestAlgorithm.reset();
        try {
            while ((length = unsignedContent.read(buff)) != -1) {
                digestAlgorithm.update(buff, 0, length);
            }
            return digestAlgorithm.digest();
        } catch (IOException e) {
            logger.error("Eccezione IO", e);
        } finally {
            if (unsignedContent != null) {
                try {
                    unsignedContent.close();
                } catch (IOException e) {
                    logger.error("Eccezione IO", e);
                }
            }
        }
        return null;
    }

    /**
     * Recupera la lista di firme da una struttura di tipo CMS settando al contempo il contenuto a cui le firme si
     * riferiscono.
     *
     * @param signedData
     *            contenuto di tipo CMS
     * @param detachedContent
     *            contenuto detached
     * 
     * @return la lista di firme
     */
    public static List<ISignature> getISigneturesFromCMSSignedData(CMSSignedData signedData, List<File> detachedContent,
            SignerType type, boolean isPDF, boolean isDetached) {

        List<ISignature> result = new ArrayList<ISignature>();

        Collection<Certificate> certificates = null;
        CertStore store = null;
        try {

            store = signedData.getCertificatesAndCRLs("Collection", "BC");
            certificates = (Collection<Certificate>) store.getCertificates(null);
            // certificates = signedData.getCertificates().getMatches(null);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        Collection<SignerInformation> signers = (Collection<SignerInformation>) signedData.getSignerInfos()
                .getSigners();
        for (SignerInformation signer : signers) {
            SignerId signerID = signer.getSID();
            ISignature signature = getISignatureFromSignerInformationAndCertificates(signer, certificates,
                    detachedContent, isPDF, isDetached);
            if (signature == null) {
                try {
                    Collection certCollection = signedData.getCertificates().getMatches(signerID);
                    Iterator certIt = certCollection.iterator();
                    X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
                    X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
                            .getCertificate(certHolder);
                    CMSSignature cmsSignature = new CMSSignature(signer, cert,
                            P7MSigner.getType(signer, isPDF, isDetached));
                    cmsSignature.setDetachedFiles(detachedContent);
                    cmsSignature.setCounterSignatures(new ArrayList<ISignature>());
                    signature = cmsSignature;
                } catch (Exception ex) {
                    logger.error("Non è stato possibile generare il certificato X509 dalla firma");
                }
            }
            if (signature != null) {
                // Sovrascrivo il tipo di firma se mi è stata passata in input (caso M7M, TSR)
                if (type != null) {
                    signature.setFormatoFirma(type);
                }
                result.add(signature);
            }
        }
        return result;
    }

    public static ISignature getISignatureFromSignerInformationAndCertificates(SignerInformation signer,
            Collection<Certificate> certificates, List<File> detachedContent, boolean isPDF, boolean isDetached) {

        SignerId signerID = signer.getSID();

        AttributeTable signedTable = signer.getSignedAttributes();
        Attribute signingCertificateV2Attr = null;
        Attribute signingCertificateAttr = null;
        if (signedTable != null) {
            signingCertificateV2Attr = (Attribute) signedTable.toHashtable()
                    .get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
            signingCertificateAttr = (Attribute) signedTable.toHashtable()
                    .get(PKCSObjectIdentifiers.id_aa_signingCertificate);
        }

        // Hash da utilizzare per identificare il certificato di firma
        byte[] certHash = null;
        String certHashAlgorithmOid = null;

        try {
            if (signingCertificateV2Attr != null) {

                // Cerca di recuperare l'hash del certificato da una struttura 'ben fatta'
                try {
                    SigningCertificateV2 signingCertificateV2 = SigningCertificateV2
                            .getInstance(signingCertificateV2Attr.getAttrValues().getObjectAt(0));
                    if (signingCertificateV2 != null) {
                        ESSCertIDv2[] essCertsV2 = signingCertificateV2.getCerts();
                        ESSCertIDv2 essCertV2 = essCertsV2[0];
                        certHash = essCertV2.getCertHash();
                        certHashAlgorithmOid = essCertV2.getHashAlgorithm().getAlgorithm().getId();
                    }
                } catch (Exception e) {

                    // Se c'è stato un errore, cerca di recuperare l'hash dal contenuto stesso
                    ASN1Sequence signingCertificateV2Encoded = (ASN1Sequence) signingCertificateV2Attr.getAttrValues()
                            .getObjectAt(0);
                    ASN1Sequence signingCertificateV2Certs = ASN1Sequence
                            .getInstance(signingCertificateV2Encoded.getObjectAt(0));
                    certHash = ASN1OctetString.getInstance(signingCertificateV2Certs.getObjectAt(0).getDERObject())
                            .getOctets();
                    // Di default l'algoritmo di hash viene posto a SHA-256
                    certHashAlgorithmOid = CMSSignedDataGenerator.DIGEST_SHA256;
                }
            } else if (signingCertificateAttr != null) {
                // Cerca di recuperare l'hash del certificato da una struttura 'ben fatta'
                try {
                    SigningCertificate signingCertificate = SigningCertificate
                            .getInstance(signingCertificateAttr.getAttrValues().getObjectAt(0));
                    if (signingCertificateAttr != null) {
                        ESSCertID[] essCertsV2 = signingCertificate.getCerts();
                        ESSCertID essCert = essCertsV2[0];
                        certHash = essCert.getCertHash();
                        certHashAlgorithmOid = CMSSignedDataGenerator.DIGEST_SHA1;
                    }
                } catch (Exception e) {

                    // Se c'è stato un errore, cerca di recuperare l'hash dal contenuto stesso
                    ASN1Sequence signingCertificateEncoded = (ASN1Sequence) signingCertificateAttr.getAttrValues()
                            .getObjectAt(0);
                    ASN1Sequence signingCertificateCerts = ASN1Sequence
                            .getInstance(signingCertificateEncoded.getObjectAt(0));
                    certHash = ASN1OctetString.getInstance(signingCertificateCerts.getObjectAt(0).getDERObject())
                            .getOctets();
                    certHashAlgorithmOid = CMSSignedDataGenerator.DIGEST_SHA1;
                }
            }
        } catch (Exception e) {
            // C'è stato un errore durante la decodifica degli attributi contenenti
            // l'hash del certificato di firma
            // e.printStackTrace();
        }

        for (Certificate certificate : certificates) {
            boolean correctCertificate = false;
            // Identifica il certificato dal suo hash
            if (certHash != null) {
                try {
                    MessageDigest digest = MessageDigest.getInstance(certHashAlgorithmOid);
                    if (digest == null) {
                        return null;
                    }
                    byte[] computedCertificateHash = digest.digest(certificate.getEncoded());
                    if (org.bouncycastle.util.Arrays.areEqual(certHash, computedCertificateHash)) {
                        correctCertificate = true;
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else if (certificate instanceof X509Certificate
                    && ((X509Certificate) certificate).getIssuerX500Principal().equals(signerID.getIssuer())
                    && signerID.getSerialNumber().equals(((X509Certificate) certificate).getSerialNumber())) {
                correctCertificate = true;
            }

            if (correctCertificate) {
                CMSSignature cmsSignature = new CMSSignature(signer, (X509Certificate) certificate,
                        P7MSigner.getType(signer, isPDF, isDetached));
                cmsSignature.setDetachedFiles(detachedContent);

                // Aggiorno la lista delle controfirme
                SignerInformationStore counterSignaturesStore = signer.getCounterSignatures();
                Collection<? extends SignerInformation> counterSignaturesInfo = counterSignaturesStore.getSigners();
                if (counterSignaturesInfo != null) {
                    List<ISignature> counterSignatures = new ArrayList<ISignature>();
                    for (SignerInformation counterSignatureInfo : counterSignaturesInfo) {
                        counterSignatures.add(getISignatureFromSignerInformationAndCertificates(counterSignatureInfo,
                                certificates, null, isPDF, isDetached));
                    }
                    cmsSignature.setCounterSignatures(counterSignatures);
                }

                return cmsSignature;
            }
        }
        return null;
    }

    @Override
    public List<ISignature> getSignatures() {
        boolean isDetached = cmsSignedData.getSignedContent() == null;
        if (detachedFiles != null && !detachedFiles.isEmpty()) {
            CMSTypedData detachedCMS = new CMSProcessableFile(detachedFiles.get(0));
            cmsSignedData = new CMSSignedData(detachedCMS, cmsSignedData.getContentInfo());
            isDetached = true;
        }
        return getISigneturesFromCMSSignedData(cmsSignedData, detachedFiles, null, false, isDetached);
    }

    @Override
    public boolean canContentBeSigned() {
        return true;
    }

    public static Collection<CRL> getCRLsFromCMSSignedData(CMSSignedData cmsSignedData) {
        X509Store store;
        Collection<CRL> crls = null;
        try {
            store = cmsSignedData.getCRLs("Collection", BouncyCastleProvider.PROVIDER_NAME);
            crls = store.getMatches(null);
            // crls = cmsSignedData.getCRLs().getMatches(null);
            return crls;
        } catch (Exception e) {
            return null;
        }

    }

    public static Collection<? extends Certificate> getCertificatesFromCMSSignedData(CMSSignedData cmsSignedData) {
        try {
            CertStore store = cmsSignedData.getCertificatesAndCRLs("Collection", BouncyCastleProvider.PROVIDER_NAME);
            return store.getCertificates(null);
            // return cmsSignedData.getCertificates().getMatches(null);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public Collection<CRL> getEmbeddedCRLs() {
        if (cmsSignedData == null) {
            try (FileInputStream fis = FileUtils.openInputStream(file)) {
                cmsSignedData = new CMSSignedData(fis);
                return getCRLsFromCMSSignedData(cmsSignedData);
            } catch (Exception e) {
            }
        }
        return getCRLsFromCMSSignedData(cmsSignedData);
    }

    @Override
    public Collection<? extends Certificate> getEmbeddedCertificates() {
        if (cmsSignedData == null) {
            try (FileInputStream fis = FileUtils.openInputStream(file)) {
                cmsSignedData = new CMSSignedData(fis);

            } catch (Exception e) {
            }
        }
        return getCertificatesFromCMSSignedData(cmsSignedData);
    }

    protected static SignerType getType(SignerInformation signer, boolean isPDF, boolean isDetached) {
        // Controllo se l'algoritmo è di tipo SHA256 e che sia presente l'attributo contenente il certificato
        boolean signed = true;
        SignerType type = isPDF ? SignerType.PDF_DSIG : (isDetached ? SignerType.P7S : SignerType.P7M);
        AttributeTable signedTable = signer.getSignedAttributes();
        if (isPDF && CMSSignedDataGenerator.DIGEST_SHA256.equals(signer.getDigestAlgOID())) {
            type = SignerType.PADES;
        }
        if (signedTable != null) {
            boolean certv2 = signedTable.toHashtable().containsKey(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
            boolean cert = signedTable.toHashtable().containsKey(PKCSObjectIdentifiers.id_aa_signingCertificate);
            if (CMSSignedDataGenerator.DIGEST_SHA256.equals(signer.getDigestAlgOID()) && !cert && certv2) {
                type = isPDF ? SignerType.PADES_BES : SignerType.CADES_BES;
                // TODO Controllo da verificare
                AttributeTable unsignedTable = signer.getUnsignedAttributes();
                if (unsignedTable != null
                        && unsignedTable.toHashtable().containsKey(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)
                        && signed) {
                    type = isPDF ? SignerType.PADES_T : SignerType.CADES_T;
                    // Controllo se sono presenti gli atttibuti CRL negli attributi unsigned
                    if (unsignedTable.toHashtable().containsKey(PKCSObjectIdentifiers.id_aa_ets_certificateRefs)
                            && unsignedTable.toHashtable().containsKey(PKCSObjectIdentifiers.id_aa_ets_revocationRefs)
                            && signed) {
                        type = isPDF ? SignerType.PADES_C : SignerType.CADES_C;
                    }
                }
            }
        }
        return type;
    }

    @Override
    public SignerType getTimeStampFormat() {
        return SignerType.P7M;
    }
}
