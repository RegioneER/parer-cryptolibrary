package it.eng.crypto.data;

import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.data.type.SignerType;
import it.eng.crypto.utils.VerificheEnums.EsitoControllo;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Map.Entry;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementa i controlli su firme di tipo CAdES. Il contenuto di un file è riconosciuto se implementa le specifiche
 * RFC5126
 *
 * @author Stefano Zennaro
 *
 */
public class CMSSigner extends P7MSigner {

    Logger log = LoggerFactory.getLogger(this.getClass().getName());
    private Map<byte[], TimeStampToken> timestamptokensBySignature = null;

    @Override
    public TimeStampToken[] getTimeStampTokens() {
        if (type.equals(super.getFormat())) {
            return super.getTimeStampTokens();
        }
        InputStream stream = null;
        ArrayList<TimeStampToken> timestampTokensList = new ArrayList<TimeStampToken>();
        if (timestamptokens == null) {
            try {
                stream = FileUtils.openInputStream(file);
                if (cmsSignedData == null) {
                    cmsSignedData = new CMSSignedData(stream);
                }
                SignerInformationStore signersStore = cmsSignedData.getSignerInfos();
                Collection<? extends SignerInformation> signers = signersStore.getSigners();

                timestamptokensBySignature = new HashMap<byte[], TimeStampToken>();

                extractTimeStampTokens(timestampTokensList, signers);

                if (timestampTokensList.size() != 0) {
                    timestamptokens = timestampTokensList.toArray(new TimeStampToken[timestampTokensList.size()]);
                }
            } catch (Exception e) {
                e.printStackTrace();
                timestamptokens = null;
            } finally {
                if (stream != null) {
                    IOUtils.closeQuietly(stream);
                }
            }

        }
        return timestamptokens;
    }

    /**
     * Restituisce true se il contenuto del file è di tipo CMS e rispetta le seguenti condizioni:
     * <ul>
     * <li>L'algoritmo di digest deve essere SHA256</li>
     * <li>Il certificato di firma deve essere presente come attributo signing-certificate oppure
     * ESS-signing-certificate-v2</li>
     * </ul>
     * Recupera inoltre il timestamp se presente come attributo non firmato (CAdES-T)
     *
     */
    @Override
    protected boolean isSignedType(CMSSignedData cmsSignedDataInternal, ValidationInfos complianceCheck) {
        // Resetto il signer
        reset();
        type = null;
        timestamptokensBySignature = null;

        boolean signed = false;

        cmsSignedData = cmsSignedDataInternal;
        SignerInformationStore signersStore = cmsSignedData.getSignerInfos();
        Collection<SignerInformation> signers = signersStore.getSigners();
        if (signers == null || signers.isEmpty()) {
            complianceCheck.addWarning("La busta CMS non contiene firme");
            signed = false;
        } else {
            // Controllo se l'algoritmo è di tipo SHA256 e che sia presente l'attributo contenente il certificato
            for (SignerInformation signer : signers) {
                AttributeTable signedTable = signer.getSignedAttributes();
                if (signedTable == null) {
                    signed = false;
                    complianceCheck.addWarning("Almeno una firma nella busta non presenta attributi firmati");
                    break;
                }
                boolean certv2 = signedTable.toHashtable()
                        .containsKey(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
                boolean cert = signedTable.toHashtable().containsKey(PKCSObjectIdentifiers.id_aa_signingCertificate);
                if (!CMSSignedDataGenerator.DIGEST_SHA256.equals(signer.getDigestAlgOID())) {
                    signed = false;
                    complianceCheck.addWarning("Almeno una firma non utilizza l'algoritmo SHA-256");
                    break;
                } else if (cert) {
                    signed = false;
                    complianceCheck.addWarning(
                            "Almeno in una firma è presente l'attributo id-aa-signingCertificate che è da utilizzare solo in firme CAdES SHA-1. Per CAdES SHA-256 utilizzare id_aa_signingCertificateV2");
                    break;
                } else if (!certv2) {
                    signed = false;
                    complianceCheck.addWarning(
                            "Almeno in una firma manca l'attributo id_aa_signingCertificateV2 richiesto da CAdES SHA-256");
                    break;
                }
                signed = true;

                // I formati CAdES_T e CAdES_C sono più restrittivi di CAdES_BES
                if (type == null) {
                    type = SignerType.CADES_BES;
                }

                // TODO Controllo da verificare
                AttributeTable unsignedTable = signer.getUnsignedAttributes();
                if (unsignedTable != null && unsignedTable.toHashtable()
                        .containsKey(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)) {
                    type = SignerType.CADES_T;
                    // Controllo se sono presenti gli atttibuti CRL negli attributi unsigned
                    if (unsignedTable.toHashtable().containsKey(PKCSObjectIdentifiers.id_aa_ets_certificateRefs)
                            && unsignedTable.toHashtable()
                                    .containsKey(PKCSObjectIdentifiers.id_aa_ets_revocationRefs)) {
                        type = SignerType.CADES_C;
                    }
                }

            }

        }
        return signed;
    }

    @Override
    public boolean isSignedType(File file, ValidationInfos complianceCheck) {
        boolean signed = false;
        try {
            cmsSignedData = getSignedData(file);
            signed = isSignedType(cmsSignedData, complianceCheck);
            if (!signed) {
                type = super.getFormat();
                signed = super.isSignedType(cmsSignedData, complianceCheck);
            }
            signed = compliantCheckBC(signed, complianceCheck);
        } catch (IOException e) {
            log.debug("Il file non è in formato BASE64");
            signed = false;
        } catch (Exception e) {
            signed = false;
        }
        return signed;
    }

    @Override
    public boolean isSignedType(byte[] content, ValidationInfos complianceCheck) {
        boolean signed = false;
        try {
            CMSSignedData cmsSignedData = new CMSSignedData(content);
            signed = isSignedType(cmsSignedData, complianceCheck);
            if (!signed) {
                type = super.getFormat();
                signed = super.isSignedType(cmsSignedData, complianceCheck);
            }
        } catch (Exception e) {
            signed = false;
        }
        return signed;
    }

    @Override
    public SignerType getFormat() {
        return type;
    }

    @Override
    public ValidationInfos validateTimeStampTokensEmbedded(TimeStampToken timeStampToken) {
        if (type.equals(super.getFormat())) {
            return super.validateTimeStampTokensEmbedded();
        }
        ValidationInfos validationInfos = new ValidationInfos();

        if (this.timestamptokens == null) {
            if (!this.isSignedType(file, validationInfos)) {
                validationInfos.addError("File non in formato: " + this.getFormat());
                validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
                return validationInfos;
            } else {
                getTimeStampTokens();
            }
        }
        byte[] signature = null;
        for (Entry<byte[], TimeStampToken> entry : timestamptokensBySignature.entrySet()) {
            if (entry.getValue().equals(timeStampToken)) {
                signature = entry.getKey();
                break;
            }
        }

        if (signature != null) {
            String hashAlgOID = timeStampToken.getTimeStampInfo().getMessageImprintAlgOID();
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance(hashAlgOID);
                TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
                TimeStampRequest request = gen.generate(hashAlgOID, digest.digest(signature));

                checkTimeStampTokenOverRequest(validationInfos, timeStampToken, request);

            } catch (NoSuchAlgorithmException e) {
                validationInfos.addError(
                        "Impossibile validare la marca poichè l'algoritmo di calcolo non è supportato: " + hashAlgOID);
                validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
            }

        }
        return validationInfos;
    }

    /*
     * @see it.eng.crypto.data.AbstractSigner#validateTimeStampTokenEmbedded()
     */
    @Override
    public ValidationInfos validateTimeStampTokensEmbedded() {
        if (type.equals(super.getFormat())) {
            return super.validateTimeStampTokensEmbedded();
        }
        ValidationInfos validationInfos = new ValidationInfos();

        if (type == SignerType.CADES_BES) {
            validationInfos.addError("Il formato: " + this.type + " non contiene una marca temporale");
            validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
            return validationInfos;
        }

        if (this.timestamptokens == null) {
            if (!this.isSignedType(file, validationInfos)) {
                validationInfos.addError("File non in formato: " + this.getFormat());
                validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
                return validationInfos;
            } else {
                getTimeStampTokens();
            }
        }

        SignerInformationStore signersStore = cmsSignedData.getSignerInfos();
        Collection<SignerInformation> signers = signersStore.getSigners();
        if (signers != null) {
            for (SignerInformation signerInfo : signers) {
                // SignerInformation signerInfo = (SignerInformation)signers.toArray()[0];
                byte[] signature = signerInfo.getSignature();
                Set<byte[]> signatures = timestamptokensBySignature.keySet();
                TimeStampToken timestamptoken = null;
                for (byte[] byteSignature : signatures) {
                    if (Arrays.areEqual(byteSignature, signature)) {
                        timestamptoken = timestamptokensBySignature.get(byteSignature);
                        break;
                    }
                }
                String hashAlgOID = timestamptoken.getTimeStampInfo().getMessageImprintAlgOID();
                MessageDigest digest;
                try {
                    digest = MessageDigest.getInstance(hashAlgOID);
                    TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
                    TimeStampRequest request = gen.generate(hashAlgOID, digest.digest(signature));

                    checkTimeStampTokenOverRequest(validationInfos, timestamptoken, request);

                } catch (NoSuchAlgorithmException e) {
                    validationInfos
                            .addError("Impossibile validare la marca poichè l'algoritmo di calcolo non è supportato: "
                                    + hashAlgOID);
                    validationInfos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
                }
            }
        }

        return validationInfos;
    }

    @Override
    public SignerType getTimeStampFormat() {
        if (type.equals(super.getFormat())) {
            return super.getTimeStampFormat();
        }
        return SignerType.CADES_T;
    }

    public boolean compliantCheckBC(boolean signed, ValidationInfos complianceCheck) {
        Collection<SignerInformation> signers = cmsSignedData.getSignerInfos().getSigners();
        if (signers != null) {
            for (SignerInformation signer : signers) {
                // Verifico la conformità con BouncyCastle chiamando il motodo che fa anche la verifica crittografica
                try {
                    Collection certCollection = (Collection) cmsSignedData.getCertificates()
                            .getMatches(signer.getSID());
                    Iterator certIt = certCollection.iterator();
                    X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
                    if (certHolder != null) {
                        X509Certificate certX509 = new JcaX509CertificateConverter().setProvider("BC")
                                .getCertificate(certHolder);
                        signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
                                .build(certX509.getPublicKey()));
                    }
                } catch (CMSException ex) {
                    // in caso di errore di conformità l'eccezione non è di tipo CMSSignerDigestMismatchException
                    // che indica, invece, un errore crittografico
                    if (!(ex instanceof CMSSignerDigestMismatchException)) {
                        complianceCheck.addWarning(ex.getMessage());
                        signed = false;
                    }

                } catch (Exception ex) {
                    log.error("Errore durante il controllo di conformità", ex);
                }
            }
        }
        return signed;
    }

    private void extractTimeStampTokens(ArrayList<TimeStampToken> timestampTokensList,
            Collection<? extends SignerInformation> signers) {
        if (signers != null) {
            for (SignerInformation signer : signers) {
                AttributeTable table = signer.getUnsignedAttributes();
                if (table == null) {
                    return;
                }
                Attribute attribute = (Attribute) table.toHashtable()
                        .get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
                // Attribute attribute = (Attribute) table.toHashtable().get(new
                // DERObjectIdentifier("1.2.840.113549.1.9.16.2.47"));
                if (attribute != null && attribute.getAttrValues() != null) {
                    TimeStampToken timestamptoken = null;
                    try {
                        timestamptoken = new TimeStampToken(new CMSSignedData(
                                attribute.getAttrValues().getObjectAt(0).getDERObject().getEncoded()));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    if (timestamptoken != null) {
                        timestampTokensList.add(timestamptoken);
                        timestamptokensBySignature.put(signer.getSignature(), timestamptoken);
                    }
                }
                SignerInformationStore counterSignatures = signer.getCounterSignatures();
                extractTimeStampTokens(timestampTokensList, counterSignatures.getSigners());
            }

        }
    }
}
