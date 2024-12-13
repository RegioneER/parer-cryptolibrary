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

package it.eng.crypto.controller.impl.signature;

import it.eng.crypto.FactorySigner;
import it.eng.crypto.controller.MasterSignerController;
import it.eng.crypto.controller.bean.InputSignerBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.bean.TrustChainCheck;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.data.signature.ISignature;
import it.eng.crypto.exception.CryptoSignerException;
import it.eng.crypto.exception.CryptoStorageException;
import it.eng.crypto.storage.ICAStorage;
import it.eng.crypto.storage.ICRLStorage;

import java.io.IOException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @101000 La classe è stata modificata per ritornare in ogni caso i certificati utilizzati e gli errori trovati!!
 *
 * Effettua il controllo di validità delle CA rispetto alla lista fornita dal eIDAS. I passi per verificare la
 * correttezza del certificato sono i seguenti:
 * <ol>
 * <li>recupero della firma del certificato e dell'issuer</li>
 * <li>verifica se nella lista dei certificatori accreditati è presente l'issuer (stesso DN)</li>
 * <li>se è presente si sbusta la firma con la chiave pubblica e si verifica il risultato con digest del
 * certificato</li>
 * </ol>
 *
 * @author Stefano Zennaro
 *
 */
public class CertificateReliability extends AbstractSignerController {

    /**
     * Proprietà restituita dal metodo
     * {@link it.eng.crypto.controller.impl.signature.CertificateReliability#getCheckProperty getCheckProperty}
     */
    public static final String CERTIFICATE_RELIABILITY_CHECK = "performCertificateReliability";
    Logger log = LoggerFactory.getLogger(MasterSignerController.class.getName());

    public String getCheckProperty() {
        return CERTIFICATE_RELIABILITY_CHECK;
    }

    // I passi per verificare la correttezza del certificato sono i seguenti:
    // - recupero la firma del certificato
    // - recupero l'issuer del certificato
    // - guardo se nella lista dei certificatori accreditati è presente l'issuer (stesso DN)
    // - se è presente trovo la chiave pubblica
    // - sbusto la firma con la chiave pubblica e verifico il risultato con digest del certificato
    public boolean execute(InputSignerBean input, OutputSignerBean output) throws ExceptionController {

        boolean result = true;
        Map<ISignature, ValidationInfos> unqualifiedSignatureValidationInfos = new HashMap<ISignature, ValidationInfos>();
        Map<ISignature, List<TrustChainCheck>> tCheckMap = new HashMap<ISignature, List<TrustChainCheck>>();
        Date referenceDate = input.getReferenceDate();
        if (referenceDate == null) {
            referenceDate = new Date();
        }

        ICAStorage certificatesAuthorityStorage = FactorySigner.getInstanceCAStorage();

        // Firme
        List<ISignature> signatures = null;
        if (output.getProperties().containsKey(OutputSignerBean.SIGNATURE_PROPERTY)) {
            signatures = (List<ISignature>) output.getProperty(OutputSignerBean.SIGNATURE_PROPERTY);
            result = populateUnqualifiedSignaturesList(tCheckMap, unqualifiedSignatureValidationInfos, signatures,
                    certificatesAuthorityStorage, input.isCheckCAOnline());

            // Popolo la lista delle firme con certificato non accreditato
            output.setProperty(OutputSignerBean.CERTIFICATE_UNQUALIFIED_PROPERTY, unqualifiedSignatureValidationInfos);

            // Popolo la lista dei certificati accreditati
            output.setProperty(OutputSignerBean.CERTIFICATE_RELIABILITY_PROPERTY, tCheckMap);
            // output.setProperty(OutputSignerBean.CRL_CA_PROPERTY, crlInfosMap);
        }
        return result;
    }

    public boolean populateUnqualifiedSignaturesList(Map<ISignature, List<TrustChainCheck>> tCheckMap,
            Map<ISignature, ValidationInfos> unqualifiedSignatureValidationInfos, List<ISignature> signatures,
            ICAStorage certificatesAuthorityStorage, boolean checkCaOnline) {

        boolean result = true;

        for (ISignature signature : signatures) {
            ValidationInfos validationInfos = new ValidationInfos();
            X509Certificate signatureCertificate = signature.getSignerBean().getCertificate();
            X500Principal issuerPrincipal = signatureCertificate.getIssuerX500Principal();
            List<TrustChainCheck> tChainList = new ArrayList<TrustChainCheck>();
            // Controllo se il certificato attuale è contenuto tra quelli accreditati
            X509Certificate qualifiedCertificate = null;
            do {
                TrustChainCheck tChainCheck = new TrustChainCheck();
                try {
                    qualifiedCertificate = certificatesAuthorityStorage.retriveCA(issuerPrincipal,
                            signerUtil.getAuthorityKeyId(signatureCertificate));
                    log.debug("Controllo se il certificato attuale è contenuto tra quelli accreditati");
                } catch (CryptoStorageException | IOException e1) {
                    log.debug("Errore durante il recupero del certificato dallo storage", e1);
                }

                if (checkCaOnline) {

                    // Potrebbe succedere che il DB delle CA non sia ancora stato riempito. Provo a controllare ONLINE.
                    if (qualifiedCertificate == null) {
                        X509Certificate caCert = signerUtil.getCACertificateOnline(signatureCertificate,
                                certificatesAuthorityStorage);
                        if (caCert != null) {
                            qualifiedCertificate = caCert;
                            try {
                                // per motivi di performance aggiungo subito la CA rischiando contesa con i job.
                                certificatesAuthorityStorage.insertCA(caCert);
                            } catch (CryptoStorageException ex) {
                                log.debug("Errore durante l'inserimento della CA ", ex);
                            }
                        }
                    }
                }
                boolean isQualified;
                if (qualifiedCertificate == null) {
                    isQualified = false;
                    validationInfos.addError("La CA non è presente nella lista dei certificatori accreditati da eIDAS");
                    log.debug("La CA non è presente nella lista dei certificatori accreditati dal eIDAS");
                } else {
                    issuerPrincipal = qualifiedCertificate.getIssuerX500Principal();
                    // Di default il certificato è accreditato se presente nella lista del eidas
                    isQualified = true;

                    // Occorre controllare che il certificato sia ancora attivo
                    if (signature.getReferenceDate().after(qualifiedCertificate.getNotAfter())) {
                        isQualified = true;
                        validationInfos.addError("Il certificato di certificazione è accreditato ma è scaduto in data: "
                                + dateFormatter.format(qualifiedCertificate.getNotAfter())
                                + " precedente al riferimento temporale: "
                                + dateFormatter.format(signature.getReferenceDate()));
                    } else if (signature.getReferenceDate().before(qualifiedCertificate.getNotBefore())) {
                        // isQualified = false;
                        isQualified = true;
                        validationInfos.addError(
                                "Il certificato di certificazione è accreditato ma è entrato in vigore in data: "
                                        + dateFormatter.format(qualifiedCertificate.getNotBefore())
                                        + " successivo al riferimento temporale: "
                                        + dateFormatter.format(signature.getReferenceDate()));
                    } // controllo che non sia stato revocato rispetto alla CRL indicata dal suo distribution point
                    else {
                        // se è una ROOT CA non effettuo la verifica CRL
                        if (issuerPrincipal.getName()
                                .equals(qualifiedCertificate.getSubjectX500Principal().getName())) {
                            log.debug("Controllo di revoca non effettuato sulla CA perchè si tratta di una ROOT CA");
                        } else {
                            // Storage delle CRL
                            ICRLStorage crlStorage = FactorySigner.getInstanceCRLStorage();
                            // Issuer del certificato di certificazione
                            X500Principal qualifiedCertificateIssuer = qualifiedCertificate.getIssuerX500Principal();
                            X509CRL qualifiedCertificateCRL = null;
                            try {
                                qualifiedCertificateCRL = crlStorage.retriveCRL(qualifiedCertificateIssuer.getName(),
                                        signerUtil.getAuthorityKeyId(qualifiedCertificate));
                            } catch (CryptoStorageException | IOException e) {
                                log.error("Errore recuperando il certificato dallo storage", e);
                            }
                            if (qualifiedCertificateCRL != null) {
                                log.debug("Recuperata la CRL dal repository cache/db; effettuo il controllo di revoca");
                                tChainCheck.setCrl(qualifiedCertificateCRL);
                                // crlInfosMap.put(signature, qualifiedCertificateCRL);
                                isQualified = checkCRL(validationInfos, qualifiedCertificate, qualifiedCertificateCRL,
                                        signature.getReferenceDate());
                            } else {
                                // Se la CRL non era presente nello storage
                                // verifico rispetto al distribution point
                                try {
                                    List<String> urlCRLDistributionPoints = signerUtil
                                            .getURLCrlDistributionPoint(qualifiedCertificate);
                                    X509CRL envelopeCrl = null;
                                    if (urlCRLDistributionPoints != null) {
                                        log.debug("CRL nel db non trovata, scarico la CRL");
                                        envelopeCrl = signerUtil.getCrlByURL(urlCRLDistributionPoints);
                                    }
                                    if (envelopeCrl != null) {
                                        tChainCheck.setCrl(envelopeCrl);
                                        // crlInfosMap.put(signature, envelopeCrl);
                                        log.debug("effettuo il controllo di revoca");
                                        isQualified = checkCRL(validationInfos, qualifiedCertificate, envelopeCrl,
                                                signature.getReferenceDate());

                                        // La CRL deve essere storicizzata
                                        try {
                                            log.debug("salvo la CRL sul DB e in cache");
                                            crlStorage.upsertCRL(envelopeCrl);
                                        } catch (CryptoStorageException e) {
                                            // TODO Auto-generated catch block
                                            e.printStackTrace();
                                        }

                                    } else {
                                        throw new CryptoSignerException();
                                    }
                                } catch (CryptoSignerException e) {
                                    // Non è stato possibile validare il certificato di certificazione rispetto alle CRL
                                    // tengo traccia dell'errore ma considero il certificato comunque accreditato
                                    // (poichè presente nella lista del eIDAS e attivo al riferimento temporale)
                                    validationInfos.addWarning(
                                            "Controllo delle CRL del certificato dell'issuer non effettuato");
                                    isQualified = true;
                                }
                            }
                        }
                    }

                }
                tChainCheck.setCerificate(qualifiedCertificate);
                tChainList.add(tChainCheck);

                unqualifiedSignatureValidationInfos.put(signature, validationInfos);
                result &= validationInfos.isValid();
            } while (qualifiedCertificate != null && !qualifiedCertificate.getIssuerX500Principal().getName()
                    .equals(qualifiedCertificate.getSubjectX500Principal().getName()));
            tCheckMap.put(signature, tChainList);
            if (performCounterSignaturesCheck) {
                List<ISignature> counterSignatures = signature.getCounterSignatures();
                result &= populateUnqualifiedSignaturesList(tCheckMap, unqualifiedSignatureValidationInfos,
                        counterSignatures, certificatesAuthorityStorage, checkCaOnline);
            }

        }

        return result;
    }

    private boolean checkCRL(ValidationInfos validationInfos, X509Certificate caCertificate, X509CRL crl, Date date) {
        log.debug("Inizio controllo di revoca");
        X509CRLEntry crlEntry = crl.getRevokedCertificate(caCertificate);
        log.debug("Fine controllo di revoca");
        // il certificato è stato revocato
        if (crlEntry != null) {
            if (date != null && crlEntry.getRevocationDate().before(date)) {
                validationInfos
                        .addError("Certificato revocato in data: " + dateFormatter.format(crlEntry.getRevocationDate())
                                + " (antecedente a: " + dateFormatter.format(date) + ")");
                return false;
            } else if (date == null) {
                validationInfos.addError(
                        "Certificato già revocato in data: " + dateFormatter.format(crlEntry.getRevocationDate()));
                return false;
            }
        }
        return true;
    }
}
