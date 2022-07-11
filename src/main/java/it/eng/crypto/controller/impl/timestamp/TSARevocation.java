package it.eng.crypto.controller.impl.timestamp;

import it.eng.crypto.FactorySigner;
import it.eng.crypto.controller.bean.DocumentAndTimeStampInfoBean;
import it.eng.crypto.controller.bean.InputTimeStampBean;
import it.eng.crypto.controller.bean.OutputTimeStampBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.exception.CryptoSignerException;
import it.eng.crypto.exception.CryptoStorageException;
import it.eng.crypto.storage.ICAStorage;
import it.eng.crypto.storage.ICRLStorage;
import it.eng.crypto.utils.VerificheEnums.EsitoControllo;
import it.eng.crypto.utils.VerificheEnums.TipoControlli;

import java.security.Principal;
import java.security.cert.CRL;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;

public class TSARevocation extends AbstractTimeStampController {

    /**
     * Proprietà restituita dal metodo
     * {@link it.eng.crypto.controller.impl.signature.CertificateReliability#getCheckProperty getCheckProperty}
     */
    public static final String TSA_REVOCATION_CHECK = "performTSARevocation";

    public String getCheckProperty() {
        return TSA_REVOCATION_CHECK;
    }

    @Override
    public boolean execute(InputTimeStampBean input, OutputTimeStampBean output) throws ExceptionController {

        // Recupero i timestamp
        List<DocumentAndTimeStampInfoBean> documentAndTimeStampInfos = output.getDocumentAndTimeStampInfos();
        if (documentAndTimeStampInfos == null || documentAndTimeStampInfos.size() == 0) {
            return false;
        }

        boolean result = true;

        ICAStorage certificatesAuthorityStorage = FactorySigner.getInstanceCAStorage();

        try {
            for (DocumentAndTimeStampInfoBean documentAndTimeStampInfo : documentAndTimeStampInfos) {

                ValidationInfos validationInfos = documentAndTimeStampInfo.getValidationInfos();
                ValidationInfos crlValidInfos = new ValidationInfos();
                TimeStampToken timeStampToken = documentAndTimeStampInfo.getTimeStampToken();
                HashMap<String, Object> validityInfo = documentAndTimeStampInfo.getValidityInfo();
                Date timestampDate = timeStampToken.getTimeStampInfo().getGenTime();
                Object qualifiedCertificateObj = validityInfo
                        .get(DocumentAndTimeStampInfoBean.PROP_QUALIFIED_CERTIFICATE);

                X509Certificate saX509Certificate = null;

                if (qualifiedCertificateObj != null) {
                    saX509Certificate = (X509Certificate) qualifiedCertificateObj;
                    Collection<CRL> embeddedCRLs = (Collection<CRL>) (timeStampToken
                            .getCertificatesAndCRLs("Collection", BouncyCastleProvider.PROVIDER_NAME).getCRLs(null));

                    /*
                     * controllo che il certificato non faccia parte della CRL indicata dalla TSA
                     */
                    // Storage delle CRL
                    ICRLStorage crlStorage = FactorySigner.getInstanceCRLStorage();
                    Principal issuerDN = saX509Certificate.getIssuerX500Principal();
                    X509CRL historicalCRL = null;
                    try {
                        historicalCRL = crlStorage.retriveCRL(issuerDN.getName(),
                                signerUtil.getAuthorityKeyId(saX509Certificate));
                    } catch (CryptoStorageException e) {
                        // Si è verificato un errore durante il recupero della CRL storicizzata
                    }

                    // Verifico se la data di prossimo aggiornamento della CRL è >= della
                    // data del riferimento temporale
                    if (historicalCRL != null && historicalCRL.getNextUpdate().after(timestampDate)) {
                        documentAndTimeStampInfo.setProperty(DocumentAndTimeStampInfoBean.PROP_CRL, historicalCRL);
                        checkCRL(validationInfos, saX509Certificate, historicalCRL, timestampDate, crlValidInfos);
                    } else {

                        // Se la CRL storica non è stato trovata oppure
                        // se il suo periodo di validità non è applicabile
                        // cerco di scaricare la CRL dal distribution point
                        try {

                            List<String> urlCRLDistributionPoints = signerUtil
                                    .getURLCrlDistributionPoint(saX509Certificate);
                            X509CRL envelopeCrl = null;
                            if (urlCRLDistributionPoints != null) {
                                envelopeCrl = signerUtil.getCrlByURL(urlCRLDistributionPoints);
                            }
                            if (envelopeCrl != null) {
                                // Se arriva qua, è stata scaricata una crl valida

                                // La CRL deve essere storicizzata
                                try {
                                    crlStorage.upsertCRL(envelopeCrl);
                                } catch (CryptoStorageException e) {
                                    // TODO Auto-generated catch block
                                    e.printStackTrace();
                                }
                                // Setto la crl usata nel bean, anche se è scaduta, infatti, deve essere persistita
                                documentAndTimeStampInfo.setProperty(DocumentAndTimeStampInfoBean.PROP_CRL,
                                        envelopeCrl);
                                // Effettuo nuovamente il controllo di validità della CRL appena scaricata
                                if (envelopeCrl != null && envelopeCrl.getNextUpdate().after(timestampDate)) {
                                    // Controllo la validità del certificato rispetto alla crl scaricata
                                    checkCRL(validationInfos, saX509Certificate, envelopeCrl, timestampDate,
                                            crlValidInfos);
                                } else {
                                    validationInfos
                                            .addError("La CRL ottenuta dal punto di distribuzione dalla TSA scade il: "
                                                    + dateFormatter.format(envelopeCrl.getNextUpdate())
                                                    + " successivo alla data del riferimento temporale usato: "
                                                    + dateFormatter.format(timestampDate));
                                    validationInfos.setEsito(EsitoControllo.CRL_SCADUTA);
                                }

                            } else {
                                throw new CryptoSignerException();
                            }

                        } catch (CryptoSignerException e) {

                            // Se si è verificato un errore durante lo scaricamento
                            // dal distribution point, oppure questo non è indicato nella busta

                            // se l'ente di certificazione del timestamp ha un issuer (diverso da se stesso)
                            // recupero il certificato dell'issuer e lo valido rispetto al riferimento temporale
                            // (non serve validarlo rispetto alle CRL perchè se fosse stato revocato
                            // dovrebbe essere stato revocato anche il certificato della TSA - a cascata)
                            X500Principal issuerPrincipal = saX509Certificate.getIssuerX500Principal();
                            X509Certificate issuerCertificate = null;
                            if (!saX509Certificate.getSubjectX500Principal().equals(issuerPrincipal)) {
                                issuerCertificate = certificatesAuthorityStorage.retriveCA(
                                        saX509Certificate.getIssuerX500Principal(),
                                        signerUtil.getAuthorityKeyId(saX509Certificate));
                            } else {
                                issuerCertificate = saX509Certificate;
                            }

                            if (issuerCertificate != null) {
                                try {
                                    issuerCertificate.checkValidity();

                                    // Se il certificato di certificazione è ancora valido
                                    // doveva essere possibile scaricare la CRL,
                                    // poichè ciò non è avvenuto, restituisco un errore
                                    validationInfos.addError(
                                            "CRL non verificabile: il certificato dell'issuer risulta ancora valido ma non è stato possibile recuperare la CRL su cui validare il certificato di firma");
                                    crlValidInfos.addError(
                                            "CRL non verificabile: il certificato dell'issuer risulta ancora valido ma non è stato possibile recuperare la CRL su cui validare il certificato di firma");
                                    crlValidInfos.setEsito(EsitoControllo.CRL_NON_SCARICABILE);
                                    result = false;
                                } catch (CertificateExpiredException e1) {

                                    // Il certificato di certificazione è scaduto
                                    // verifico sulle CRL della busta
                                    boolean existsEmbeddedCRLReferredToIssuer = false;
                                    if (embeddedCRLs != null) {

                                        for (CRL embeddedCRL : embeddedCRLs) {
                                            if (embeddedCRL instanceof X509CRL) {
                                                X509CRL x509EmbeddedCRL = (X509CRL) embeddedCRL;

                                                // Verifico che la CRL sia relativa al certificato dell'issuer
                                                try {
                                                    x509EmbeddedCRL.verify(issuerCertificate.getPublicKey());

                                                    // Verifico che la CRL della busta abbia una data di
                                                    // validità successiva al riferimento temporale
                                                    if (x509EmbeddedCRL.getNextUpdate().after(timestampDate)) {
                                                        documentAndTimeStampInfo.setProperty(
                                                                DocumentAndTimeStampInfoBean.PROP_CRL, embeddedCRL);
                                                        checkCRL(validationInfos, saX509Certificate,
                                                                (X509CRL) embeddedCRL, timestampDate, crlValidInfos);

                                                        // Tengo traccia che almeno una CRL nella busta è relativa
                                                        // al certificato dell'issuer
                                                        existsEmbeddedCRLReferredToIssuer |= true;

                                                        // Se è valida si può storicizzare
                                                        try {
                                                            crlStorage.upsertCRL(x509EmbeddedCRL);
                                                        } catch (CryptoStorageException e2) {
                                                            e2.printStackTrace();
                                                        }
                                                    }

                                                } catch (Exception e2) {

                                                    // Una CRL nella busta non è relativa al certificato dell'issuer
                                                    existsEmbeddedCRLReferredToIssuer |= false;
                                                }

                                            }
                                        }

                                        if (!existsEmbeddedCRLReferredToIssuer) {
                                            validationInfos.addError("CRL non verificabile: nella busta sono presenti "
                                                    + embeddedCRLs.size()
                                                    + " CRL ma nessuna è valida rispetto al certificato dell'issuer");
                                            crlValidInfos.addError("CRL non verificabile: nella busta sono presenti "
                                                    + embeddedCRLs.size()
                                                    + " CRL ma nessuna è valida rispetto al certificato dell'issuer");
                                            crlValidInfos.setEsito(EsitoControllo.CRL_NON_VALIDA);
                                        }
                                    }
                                }
                            } else {
                                validationInfos.addError(
                                        "CRL non verificabile: non è stato possibile reperire il certificato dell'issuer");
                                crlValidInfos.addError(
                                        "CRL non verificabile: non è stato possibile reperire il certificato dell'issuer");
                                crlValidInfos.setEsito(EsitoControllo.CRL_NON_SCARICABILE);
                            }
                        }
                    }
                } else {
                    validationInfos.addWarning(
                            "Il certificato della TSA non è attendibile il controllo CRL non sarà effettuato");
                    crlValidInfos.addError(
                            "Il certificato della TSA non è attendibile il controllo CRL non sarà effettuato");
                    crlValidInfos.setEsito(EsitoControllo.NON_NECESSARIO);
                }
                documentAndTimeStampInfo.setProperty(TipoControlli.CRL.name(), crlValidInfos);

            }
        } catch (Exception e) {
            throw new ExceptionController(e);
        }

        return result;
    }

    private void checkCRL(ValidationInfos validationInfos, X509Certificate signatureCertificate, X509CRL crl, Date date,
            ValidationInfos crlValidInfos) {
        X509CRLEntry crlEntry = crl.getRevokedCertificate(signatureCertificate);
        // il certificato è stato revocato
        if (crlEntry != null) {
            if (date != null && crlEntry.getRevocationDate().before(date)) {
                validationInfos.addError("Certificato revocato in data: " + crlEntry.getRevocationDate()
                        + " (antecedente a: " + date + ")");
                crlValidInfos.addError("Certificato revocato in data: " + crlEntry.getRevocationDate()
                        + " (antecedente a: " + date + ")");
                crlValidInfos.setEsito(EsitoControllo.CERTIFICATO_REVOCATO);
            } else if (date == null) {
                validationInfos.addError("Certificato già revocato in data: " + crlEntry.getRevocationDate());
                crlValidInfos.addError("Certificato già revocato in data: " + crlEntry.getRevocationDate());
                crlValidInfos.setEsito(EsitoControllo.CERTIFICATO_REVOCATO);
            }
        }
    }
}
