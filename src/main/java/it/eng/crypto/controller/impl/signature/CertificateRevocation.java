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

package it.eng.crypto.controller.impl.signature;

import java.io.IOException;
import java.security.Principal;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.eng.crypto.FactorySigner;
import it.eng.crypto.controller.MasterSignerController;
import it.eng.crypto.controller.bean.InputSignerBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.bean.TrustChainCheck;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.data.SignerUtil;
import it.eng.crypto.data.signature.ISignature;
import it.eng.crypto.exception.CryptoSignerException;
import it.eng.crypto.exception.CryptoStorageException;
import it.eng.crypto.storage.ICRLStorage;
import it.eng.crypto.utils.VerificheEnums.EsitoControllo;

/**
 * Prende in considerazione come riferimento temporale il timestamp in input (se presente) oppure la
 * data attuale. Verifica la validità dei certificati di firma rispetto
 * <ol>
 * <li>Alle CRL recuperate dalla firma digitale (se presenti)</li>
 * <li>Alla CRL scaricata dal distribution point indicato nella busta è il controllo prende in
 * considerazione solamente le CRL valide al riferimento temporale, presenti tra gli attributi
 * firmati di ciascuna firma</li>
 * <li>Alla CRL fornita in input deve essere valida rispetto al riferimento temporale</li>
 * <li>Alla CRL storicizzata al momento del riferimento temporale</li>
 * </ol>
 *
 * @author Stefano Zennaro
 */
public class CertificateRevocation extends AbstractSignerController {

    public static final String CERTIFICATE_REVOCATION_CHECK = "performCertificateRevocation";
    Logger log = LoggerFactory.getLogger(MasterSignerController.class.getName());
    public boolean checkCertificateExpiration = true;

    public String getCheckProperty() {
        return CERTIFICATE_REVOCATION_CHECK;
    }

    public boolean execute(InputSignerBean input, OutputSignerBean output)
            throws ExceptionController {

        boolean result = true;

        // Date referenceDate = input.getReferenceDate();
        // if (referenceDate==null)
        // referenceDate = Calendar.getInstance().getTime();
        //
        /*
         * TODO: vecchia implementazione da rimuovere
         */
        // DocumentAndTimeStampInfoBean timeStampInfo= input.getDocumentAndTimeStampInfo();
        // // recupero il riferimento temporale dal timestamptoken
        // Date referenceDate = null;
        // try{
        // referenceDate = timeStampInfo.getTimeStampToken().getTimeStampInfo().getGenTime();
        // }catch(Exception e){
        // referenceDate = Calendar.getInstance().getTime();
        // }

        Map<ISignature, ValidationInfos> validationInfosMap = new HashMap<ISignature, ValidationInfos>();
        Map<ISignature, X509CRL> crlInfosMap = new HashMap<ISignature, X509CRL>();
        if (output.getProperties().containsKey(OutputSignerBean.SIGNATURE_PROPERTY)) {
            List<ISignature> signatures = (List<ISignature>) output
                    .getProperty(OutputSignerBean.SIGNATURE_PROPERTY);
            result = populateValidationInfosMapFromInputOutput(validationInfosMap, crlInfosMap,
                    input, output, signatures);

            // Aggiungo le informazioni all'outputBean
            output.setProperty(OutputSignerBean.CRL_VALIDATION_PROPERTY, validationInfosMap);
            output.setProperty(OutputSignerBean.CRL_PROPERTY, crlInfosMap);
        }
        return result;
    }

    private boolean populateValidationInfosMapFromInputOutput(
            Map<ISignature, ValidationInfos> validationInfosMap,
            Map<ISignature, X509CRL> crlInfosMap, InputSignerBean input, OutputSignerBean output,
            List<ISignature> signatures) {

        Map<ISignature, ValidationInfos> expiredCertificates = (Map<ISignature, ValidationInfos>) output
                .getProperty(OutputSignerBean.CERTIFICATE_EXPIRATION_PROPERTY);
        Map<ISignature, List<TrustChainCheck>> certificateReliabilityMap = (Map<ISignature, List<TrustChainCheck>>) output
                .getProperty(OutputSignerBean.CERTIFICATE_RELIABILITY_PROPERTY);
        Collection<CRL> embeddedCRLs = input.getSigner().getEmbeddedCRLs();
        CRL inputCRL = input.getCrl();
        Collection<? extends Certificate> embeddedCertificates = input.getSigner()
                .getEmbeddedCertificates();

        boolean result = true;

        // Storage delle CRL
        ICRLStorage crlStorage = FactorySigner.getInstanceCRLStorage();

        for (ISignature signature : signatures) {

            ValidationInfos validationInfos = new ValidationInfos();

            /*
             * Verifico se il certificato era già scaduto alla data di riferimento temporale Solo se
             * la configurazione prevede questa verifica
             */
            ValidationInfos certificateExpirationInfo = null;
            if (isCheckCertificateExpiration()) {
                certificateExpirationInfo = expiredCertificates.get(signature);
            }
            if (certificateExpirationInfo != null && !certificateExpirationInfo.isValid()) {
                if (certificateExpirationInfo.getEsito()
                        .equals(EsitoControllo.CERTIFICATO_ERRATO)) {
                    validationInfos
                            .addError("Certificato di firma errato, verifica CRL non effettuata");
                } else {
                    validationInfos.addError(
                            "Certificato scaduto alla data del riferimento temporale, verifica CRL non effettuata");
                }
                validationInfos.setEsito(EsitoControllo.NON_NECESSARIO);
            } else {
                X509Certificate signatureCertificate = signature.getSignerBean().getCertificate();
                Principal issuerDN = signatureCertificate.getIssuerX500Principal();

                /*
                 * Recupero la CRL dell'issuer del certificato
                 */

                X509CRL historicalCRL = null;
                try {
                    historicalCRL = crlStorage.retriveCRL(issuerDN.getName(),
                            signerUtil.getAuthorityKeyId(signatureCertificate));
                } catch (CryptoStorageException | IOException e) {
                    log.error("Errore recuperando il certificato dallo storage", e);
                }
                // TODO MQ: verificare se aggiungere questo controllo anche durante il
                // CertificateReliability
                // Verifico se la data di prossimo aggiornamento della CRL è >= della
                // data del riferimento temporale
                if (historicalCRL != null
                        && historicalCRL.getNextUpdate().after(signature.getReferenceDate())) {
                    log.debug(
                            "Recuperata la CRL dal repository cache/db; effettuo il controllo di revoca");
                    checkCRL(validationInfos, signature, historicalCRL, crlInfosMap);
                } else {

                    // Se la CRL storica non è stato trovata oppure
                    // se il suo periodo di validità non è applicabile
                    // cerco di scaricare la CRL dal distribution point
                    try {
                        log.debug("CRL nel db non trovata oppure scaduta, scarico la CRL");
                        List<String> urlCRLDistributionPoints = signerUtil
                                .getURLCrlDistributionPoint(signatureCertificate);

                        if (urlCRLDistributionPoints != null) {
			    X509CRL distributionPointCRL = signerUtil.getCrlByURL(urlCRLDistributionPoints,
				    input.getHttpCrlTimeoutConnection(),
				    input.getHttpCrlSocketTimeout(),
				    input.getLdapCrlTimeoutConnection());

                            // Se la CRL è stata scaricata correttamente
                            // allora questa deve essere storicizzata
                            if (distributionPointCRL == null) {
                                throw new CryptoSignerException();
                            }
                            try {
                                log.debug("salvo la CRL sul DB e in cache");
                                crlStorage.upsertCRL(distributionPointCRL);
                            } catch (CryptoStorageException e) {
                                // TODO Auto-generated catch block
                                e.printStackTrace();
                            }
                            // Effettuo nuovamente il controllo di validità della CRL appena
                            // scaricata
                            if (distributionPointCRL != null && distributionPointCRL.getNextUpdate()
                                    .after(signature.getReferenceDate())) {
                                log.debug("effettuo il controllo di revoca");
                                checkCRL(validationInfos, signature, distributionPointCRL,
                                        crlInfosMap);
                            } else {
                                validationInfos.addError(
                                        "La CRL ottenuta dal punto di distribuzione dalla CA scade il: "
                                                + dateFormatter.format(
                                                        distributionPointCRL.getNextUpdate())
                                                + " precedente alla data del riferimento temporale usato: "
                                                + dateFormatter
                                                        .format(signature.getReferenceDate()));
                                validationInfos.setEsito(EsitoControllo.CRL_SCADUTA);
                                // anche in caso di CRL_SCADUTA devo popolare la mappa: la CRL deve
                                // essere persistita
                                crlInfosMap.put(signature, distributionPointCRL);
                            }

                        } else {
                            throw new CryptoSignerException();
                        }

                    } catch (CryptoSignerException e) {

                        // Se si è verificato un errore durante lo scaricamento
                        // dal distribution point, oppure questo non è indicato nella busta
                        // si verifica se il certificato dell'issuer è ancora valido

                        X509Certificate issuerCertificate = null;
                        // TODO controllo se la mappa è diversa da null ... potrei aver non
                        // effettuato il controllo di
                        // Ceritificate Reliability
                        if (certificateReliabilityMap != null
                                && certificateReliabilityMap.get(signature) != null) {
                            issuerCertificate = certificateReliabilityMap.get(signature).get(0)
                                    .getCerificate();
                        }

                        if (issuerCertificate == null) {
                            issuerCertificate = SignerUtil.getCertificateFromCollection(issuerDN,
                                    embeddedCertificates);
                        }

                        if (issuerCertificate != null) {
                            try {
                                issuerCertificate.checkValidity();
                                // Se il certificato di certificazione è ancora valido
                                // doveva essere possibile scaricare la CRL,
                                // poichè ciò non è avvenuto, restituisco un errore
                                validationInfos.addError(
                                        "CRL non verificabile, il certificato dell'issuer risulta ancora valido ma non è stato possibile recuperare la CRL su cui validare il certificato di firma");
                                validationInfos.setEsito(EsitoControllo.CRL_NON_SCARICABILE);
                            } catch (CertificateExpiredException e1) {

                                // Il certificato di certificazione è scaduto
                                // verifico sulle CRL della busta
                                boolean existsEmbeddedCRLReferredToIssuer = false;
                                if (embeddedCRLs != null && embeddedCRLs.size() != 0) {

                                    for (CRL embeddedCRL : embeddedCRLs) {
                                        if (embeddedCRL instanceof X509CRL) {
                                            X509CRL x509EmbeddedCRL = (X509CRL) embeddedCRL;

                                            // Verifico che la CRL sia relativa al certificato
                                            // dell'issuer
                                            try {
                                                x509EmbeddedCRL
                                                        .verify(issuerCertificate.getPublicKey());

                                                // Verifico che la CRL della busta abbia una data di
                                                // validità successiva al riferimento temporale
                                                if (x509EmbeddedCRL.getNextUpdate()
                                                        .after(signature.getReferenceDate())) {

                                                    checkCRL(validationInfos, signature,
                                                            (X509CRL) embeddedCRL, crlInfosMap);

                                                    // Tengo traccia che almeno una CRL nella busta
                                                    // è relativa
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

                                                // Una CRL nella busta non è relativa al
                                                // certificato
                                                // dell'issuer
                                                existsEmbeddedCRLReferredToIssuer |= false;
                                            }

                                        }
                                    }

                                    if (!existsEmbeddedCRLReferredToIssuer) {
                                        validationInfos.addWarning("Nella busta sono presenti "
                                                + embeddedCRLs.size()
                                                + " CRL ma nessuna è valida rispetto al certificato dell'issuer");
                                        validationInfos.setEsito(EsitoControllo.CRL_NON_VALIDA);
                                    }
                                }

                                // Non sono presenti CRL nella busta oppure nessuna delle presenti
                                // è
                                // valida
                                // verifico rispetto alla CRL in input
                                if (embeddedCRLs == null || embeddedCRLs.size() == 0
                                        || !existsEmbeddedCRLReferredToIssuer) {
                                    if (inputCRL instanceof X509CRL) {
                                        X509CRL x509InputCRL = (X509CRL) inputCRL;
                                        try {
                                            x509InputCRL.verify(issuerCertificate.getPublicKey());
                                            if (x509InputCRL.getNextUpdate()
                                                    .after(signature.getReferenceDate())) {
                                                checkCRL(validationInfos, signature, x509InputCRL,
                                                        crlInfosMap);

                                                // Se è valida si può storicizzare
                                                try {
                                                    crlStorage.upsertCRL(x509InputCRL);
                                                } catch (CryptoStorageException e2) {
                                                    e2.printStackTrace();
                                                }
                                            } else {
                                                validationInfos.addError(
                                                        "CRL non verificabile, errore durante la validazione con CRL in input, la CRL non è valida per il riferimento temporale considerato: "
                                                                + dateFormatter.format(signature
                                                                        .getReferenceDate()));
                                                validationInfos
                                                        .setEsito(EsitoControllo.CRL_SCADUTA);
                                                // anche in caso di CRL_SCADUTA devo popolare la
                                                // mappa: la CRL deve
                                                // essere persistita
                                                crlInfosMap.put(signature, x509InputCRL);
                                            }

                                        } catch (Exception e2) {
                                            validationInfos.addError(
                                                    "CRL non verificabile, la CRL in input non si riferisce al certificato dell'issuer");
                                            validationInfos.setEsito(EsitoControllo.CRL_NON_VALIDA);
                                        }
                                    } else {
                                        validationInfos.addError(
                                                "CRL non verificabile, non si dispone di una CRL su cui validare il certificato di firma");
                                        Calendar cal = Calendar.getInstance();
                                        cal.set(2009, Calendar.DECEMBER, 3);
                                        // Se il certificato della CA è scaduto prima del 3 dicembre
                                        // 2009 la CRL
                                        // potrebbe non esserci
                                        if (issuerCertificate.getNotAfter().before(cal.getTime())) {
                                            validationInfos.setEsito(
                                                    EsitoControllo.CERTIFICATO_SCADUTO_3_12_2009);
                                        } else {
                                            validationInfos
                                                    .setEsito(EsitoControllo.CRL_NON_SCARICABILE);
                                        }

                                    }
                                }

                            } catch (CertificateNotYetValidException e1) {
                                validationInfos.addError(
                                        "CRL non verificabile, il certificato dell'issuer risulta non essere ancora valido");
                                validationInfos.setEsito(EsitoControllo.CRL_NON_SCARICABILE);
                            }

                        } else {
                            validationInfos.addError(
                                    "CRL non verificabile, non si dispone di una CRL su cui validare il certificato di firma e non è stato possibile reperire il certificato dell'issuer");
                            validationInfos.setEsito(EsitoControllo.CRL_NON_SCARICABILE);
                        }

                    }

                }

            }

            if (validationInfos.isValid()) {
                validationInfos.setEsito(EsitoControllo.POSITIVO);
            }
            // Aggiungo il risultato della validazione della CRL della firma
            validationInfosMap.put(signature, validationInfos);
            result &= validationInfos.isValid();

            if (performCounterSignaturesCheck) {
                List<ISignature> counterSignatures = signature.getCounterSignatures();
                result &= populateValidationInfosMapFromInputOutput(validationInfosMap, crlInfosMap,
                        input, output, counterSignatures);
            }
        }
        return result;
    }

    private void checkCRL(ValidationInfos validationInfos, ISignature signature, X509CRL crl,
            Map<ISignature, X509CRL> crlInfosMap) {
        // Popolo la mappa con la CRL usata
        crlInfosMap.put(signature, crl);
        Date date = signature.getReferenceDate();
        X509Certificate signatureCertificate = signature.getSignerBean().getCertificate();
        log.debug("Inizio controllo di revoca");
        X509CRLEntry crlEntry = crl.getRevokedCertificate(signatureCertificate);
        log.debug("Fine controllo di revoca");
        // il certificato è stato revocato
        if (crlEntry != null) {
            String reason = (crlEntry.getRevocationReason() != null)
                    ? " - Motivo di revoca: " + crlEntry.getRevocationReason().toString()
                    : "";
            if (date != null && crlEntry.getRevocationDate().before(date)) {
                validationInfos.addError("Certificato revocato in data: "
                        + dateFormatter.format(crlEntry.getRevocationDate()) + " (antecedente a: "
                        + dateFormatter.format(date) + ")" + reason);
                validationInfos.setEsito(EsitoControllo.CERTIFICATO_REVOCATO);
            } else if (date == null) {
                validationInfos.addError("Certificato già revocato in data: "
                        + dateFormatter.format(crlEntry.getRevocationDate()) + reason);
                validationInfos.setEsito(EsitoControllo.CERTIFICATO_REVOCATO);
            }
        }

    }

    public boolean isCheckCertificateExpiration() {
        return checkCertificateExpiration;
    }

    public void setCheckCertificateExpiration(boolean checkCertificateExpiration) {
        this.checkCertificateExpiration = checkCertificateExpiration;
    }
}
