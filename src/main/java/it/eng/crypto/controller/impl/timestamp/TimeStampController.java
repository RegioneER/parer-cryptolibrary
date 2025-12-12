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

package it.eng.crypto.controller.impl.timestamp;

import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.tsp.GenTimeAccuracy;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Store;

import it.eng.crypto.FactorySigner;
import it.eng.crypto.controller.ITimeStampController;
import it.eng.crypto.controller.ITimeStampValidator;
import it.eng.crypto.controller.bean.DocumentAndTimeStampInfoBean;
import it.eng.crypto.controller.bean.TimeStampValidityBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.data.AbstractSigner;
import it.eng.crypto.data.SignerUtil;
import it.eng.crypto.exception.CryptoSignerException;
import it.eng.crypto.exception.CryptoStorageException;
import it.eng.crypto.storage.ICAStorage;
import it.eng.crypto.storage.ICRLStorage;

/**
 * Consente di effettuare l'analisi di file contenenti marche temporali (metodo
 * {@link checkTimeStamps(File)} ), oppure associati a marche temporali detached (metodo
 * {@link checkTimeStamps(File, File)} ]. Nel caso siano presenti delle marche temporali aggiuntive
 * (che estendono quella da analizzare), esse devono essere specificate come parametri aggiuntivi
 * del metodo corrispondente all'interno di un array, ad esempio:<br/>
 * <code>checkTimeStamps(contentFileWithTimeStamp, new File[]{timeStampExtension1 timestampExtension2,..})</code>
 *
 * @author Stefano Zennaro
 *
 */
@SuppressWarnings("unchecked")
public class TimeStampController implements ITimeStampController {

    private AbstractSigner signer;

    private List<TimeStampValidityBean> timeStampValidity;

    private ITimeStampValidator timeStampValidator;

    private SignerUtil signerUtil = SignerUtil.newInstance();

    private void populateCommonAttributes(DocumentAndTimeStampInfoBean documentAndTimeStampInfo,
            ValidationInfos validationInfos, boolean executeCurrentDateValidation) {

        TimeStampToken timeStampToken = documentAndTimeStampInfo.getTimeStampToken();

        /*
         * Tipo di algorimto utilizzato durante la generazione dell'hash del messaggio - è
         * l'algoritmo impiegato per effettuare l'impronta del file marcato
         */
        TimeStampTokenInfo tokenInfo = timeStampToken.getTimeStampInfo();
        documentAndTimeStampInfo.setProperty(DocumentAndTimeStampInfoBean.PROP_HASH_ALGORITHM,
                tokenInfo.getMessageImprintAlgOID());

        /*
         * Riferimento temporale in millisecondi (se disponibili) della marca
         */
        GenTimeAccuracy accuracy = tokenInfo.getGenTimeAccuracy();
        Long millis = accuracy != null
                ? tokenInfo.getGenTime().getTime() + tokenInfo.getGenTimeAccuracy().getMillis()
                : tokenInfo.getGenTime().getTime();
        documentAndTimeStampInfo.setProperty(DocumentAndTimeStampInfoBean.PROP_MILLISECS,
                millis.toString());

        /*
         * Data del riferimento temporale
         */
        Date timestampDate = new Date(tokenInfo.getGenTime().getTime());
        documentAndTimeStampInfo.setProperty(DocumentAndTimeStampInfoBean.PROP_DATE, timestampDate);

        /*
         * Controlla se il certificato della TSA è nella lista dei certificati accreditati
         */
        Boolean isCertificateInList = false;
        Collection<CRL> embeddedCRLs = null;
        Collection<Certificate> saCertificates = null;

        // Seriale identificativo della TSA
        BigInteger tsaSerial = timeStampToken.getSID().getSerialNumber();
        try {

            // Refactored: Use Store and JcaX509CertificateConverter for certificates
            Store certStore = timeStampToken.getCertificates();
            Collection<org.bouncycastle.cert.X509CertificateHolder> certHolders = certStore
                    .getMatches(null);
            saCertificates = new java.util.ArrayList<>();
            org.bouncycastle.cert.jcajce.JcaX509CertificateConverter certConverter = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                    .setProvider("BC");
            for (org.bouncycastle.cert.X509CertificateHolder holder : certHolders) {
                saCertificates.add(certConverter.getCertificate(holder));
            }

            // Refactored: Use Store and convert X509CRLHolder to CRL
            Store crlStore = timeStampToken.getCRLs();
            Collection<org.bouncycastle.cert.X509CRLHolder> crlHolders = crlStore.getMatches(null);
            embeddedCRLs = new java.util.ArrayList<>();
            for (org.bouncycastle.cert.X509CRLHolder crlHolder : crlHolders) {
                java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
                        .getInstance("X.509");
                java.io.InputStream in = new java.io.ByteArrayInputStream(crlHolder.getEncoded());
                embeddedCRLs.add((CRL) cf.generateCRL(in));
                in.close();
            }
            // Refactored: end

            for (Certificate saCertificate : saCertificates) {
                if (saCertificate instanceof X509Certificate) {

                    X509Certificate saX509Certificate = (X509Certificate) saCertificate;
                    // Controllo se il certificato corrisponde a quello della TSA
                    if (saX509Certificate.getSerialNumber().equals(tsaSerial)) {

                        // # various interpretations of the RDN fields exist
                        // # the following are presented as generally accepted
                        // # values. In the case of personal certificates bizarre values
                        // # can appear in the fields
                        // # C = ISO3166 two character country code
                        // # ST = state or province
                        // # L = Locality; generally means city
                        // # O = Organization - Company Name
                        // # OU = Organization Unit - division or unit
                        // # CN = CommonName - entity name e.g. www.example.com
                        documentAndTimeStampInfo.setProperty(DocumentAndTimeStampInfoBean.PROP_SID,
                                saX509Certificate.getSubjectX500Principal().getName());

                        // Controllo se il certificato di firma è attendibile
                        ICAStorage certificatesAuthorityStorage = FactorySigner
                                .getInstanceCAStorage();

                        X509Certificate qualifiedCertificate = certificatesAuthorityStorage
                                .retriveCA(saX509Certificate.getSubjectX500Principal(),
                                        SignerUtil.getSubjectKeyId(saX509Certificate));
                        if (qualifiedCertificate == null) {
                            isCertificateInList = false;
                            validationInfos.addError("Il certificato della TSA non è accreditato");
                        } else {
                            PublicKey publicKey = qualifiedCertificate.getPublicKey();
                            if (org.bouncycastle.util.Arrays.constantTimeAreEqual(
                                    saCertificate.getPublicKey().getEncoded(),
                                    qualifiedCertificate.getPublicKey().getEncoded())) {

                                /*
                                 * Verifico la data di scadenza temporale del certificato indicato
                                 * nello storage
                                 */
                                if (timestampDate.after(qualifiedCertificate.getNotAfter())) {
                                    validationInfos.addError(
                                            "La data di generazione della marca temporale: "
                                                    + timestampDate
                                                    + " è successiva alla data di scadenza del certificato: "
                                                    + qualifiedCertificate.getNotAfter());
                                    isCertificateInList = false;
                                } else if (timestampDate
                                        .before(qualifiedCertificate.getNotBefore())) {
                                    validationInfos.addError(
                                            "La data di generazione della marca temporale: "
                                                    + timestampDate
                                                    + " è precedente alla data di inizio validita' del certificato: "
                                                    + qualifiedCertificate.getNotBefore());
                                    isCertificateInList = false;
                                } else {
                                    isCertificateInList = true;
                                }
                            } else {
                                validationInfos.addError(
                                        "La TSA indicata nel timestamp non corrisponde a quella salvata nello storage");
                                isCertificateInList = false;
                            }
                        }

                        if (isCertificateInList.booleanValue()) {
                            /*
                             * controllo che il certificato non faccia parte della CRL indicata
                             * dalla TSA
                             */
                            // Storage delle CRL
                            ICRLStorage crlStorage = FactorySigner.getInstanceCRLStorage();
                            Principal issuerDN = saX509Certificate.getIssuerX500Principal();
                            X509CRL historicalCRL = null;
                            try {
                                historicalCRL = crlStorage.retriveCRL(issuerDN.getName(),
                                        signerUtil.getAuthorityKeyId(saX509Certificate));
                            } catch (CryptoStorageException e) {

                            }

                            // Verifico se la data di prossimo aggiornamento della CRL è >= della
                            // data del riferimento temporale
                            if (historicalCRL != null
                                    && historicalCRL.getNextUpdate().after(timestampDate)) {
                                checkCRL(validationInfos, saX509Certificate, historicalCRL,
                                        timestampDate);
                            } else {

                                // Se la CRL storica non è stato trovata oppure
                                // se il suo periodo di validità non è applicabile
                                // cerco di scaricare la CRL dal distribution point
                                try {

                                    List<String> urlCRLDistributionPoints = signerUtil
                                            .getURLCrlDistributionPoint(saX509Certificate);
                                    X509CRL envelopeCrl = null;
                                    if (urlCRLDistributionPoints != null) {
					envelopeCrl = signerUtil.getCrlByURL(urlCRLDistributionPoints,
						documentAndTimeStampInfo.getHttpCrlTimeoutConnection(),
						documentAndTimeStampInfo.getHttpCrlSocketTimeout(),
						documentAndTimeStampInfo.getLdapCrlTimeoutConnection());
				      }
                                    if (envelopeCrl != null) {
                                        // Se arriva qua, è stata scaricata una crl valida

                                        // La CRL deve essere storicizzata
                                        try {
                                            crlStorage.upsertCRL(envelopeCrl);
                                        } catch (CryptoStorageException e) {
                                            e.printStackTrace();
                                        }

                                        // Controllo la validita' del certificato rispetto alla crl
                                        // scaricata
                                        checkCRL(validationInfos, saX509Certificate, envelopeCrl,
                                                timestampDate);
                                    } else {
                                        throw new CryptoSignerException();
                                    }

                                } catch (CryptoSignerException e) {

                                    // Se si è verificato un errore durante lo scaricamento
                                    // dal distribution point, oppure questo non è indicato nella
                                    // busta

                                    // se l'ente di certificazione del timestamp ha un issuer
                                    // (diverso da se stesso)
                                    // recupero il certificato dell'issuer e lo valido rispetto al
                                    // riferimento temporale
                                    // (non serve validarlo rispetto alle CRL perchè se fosse stato
                                    // revocato
                                    // dovrebbe essere stato revocato anche il certificato della TSA
                                    // - a cascata)
                                    X500Principal issuerPrincipal = saX509Certificate
                                            .getIssuerX500Principal();
                                    X509Certificate issuerCertificate = null;
                                    if (!saX509Certificate.getSubjectX500Principal()
                                            .equals(issuerPrincipal)) {
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
                                            // poichè cio' non è avvenuto, restituisco un errore
                                            validationInfos.addError(
                                                    "CRL non verificabile: il certificato dell'issuer risulta ancora valido ma non è stato possibile recuperare la CRL su cui validare il certificato di firma");
                                        } catch (CertificateExpiredException e1) {

                                            // Il certificato di certificazione è scaduto
                                            // verifico sulle CRL della busta
                                            boolean existsEmbeddedCRLReferredToIssuer = false;
                                            if (embeddedCRLs != null) {

                                                for (CRL embeddedCRL : embeddedCRLs) {
                                                    if (embeddedCRL instanceof X509CRL) {
                                                        X509CRL x509EmbeddedCRL = (X509CRL) embeddedCRL;

                                                        // Verifico che la CRL sia relativa al
                                                        // certificato dell'issuer
                                                        try {
                                                            x509EmbeddedCRL.verify(issuerCertificate
                                                                    .getPublicKey());

                                                            // Verifico che la CRL della busta abbia
                                                            // una data di
                                                            // validita' successiva al riferimento
                                                            // temporale
                                                            if (x509EmbeddedCRL.getNextUpdate()
                                                                    .after(timestampDate)) {

                                                                checkCRL(validationInfos,
                                                                        saX509Certificate,
                                                                        (X509CRL) embeddedCRL,
                                                                        timestampDate);

                                                                // Tengo traccia che almeno una CRL
                                                                // nella busta è
                                                                // relativa
                                                                // al certificato dell'issuer
                                                                existsEmbeddedCRLReferredToIssuer |= true;

                                                                // Se è valida si può storicizzare
                                                                try {
                                                                    crlStorage.upsertCRL(
                                                                            x509EmbeddedCRL);
                                                                } catch (CryptoStorageException e2) {
                                                                    e2.printStackTrace();
                                                                }
                                                            }

                                                        } catch (Exception e2) {

                                                            // Una CRL nella busta non è relativa
                                                            // al
                                                            // certificato
                                                            // dell'issuer
                                                            existsEmbeddedCRLReferredToIssuer |= false;
                                                        }

                                                    }
                                                }

                                                if (!existsEmbeddedCRLReferredToIssuer) {
                                                    validationInfos.addWarning(
                                                            "CRL non verificabile: nella busta sono presenti "
                                                                    + embeddedCRLs.size()
                                                                    + " CRL ma nessuna è valida rispetto al certificato dell'issuer");
                                                }
                                            }
                                        }
                                    } else {
                                        validationInfos.addWarning(
                                                "CRL non verificabile: non è stato possibile reperire il certificato dell'issuer");
                                    }
                                }
                            }

                        }

                    }

                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        documentAndTimeStampInfo.setProperty(
                DocumentAndTimeStampInfoBean.PROP_RECOGNIZED_CERTIFICATE,
                isCertificateInList.toString());

        /*
         * Controllo della validita' attuale del timestamp
         */
        if (executeCurrentDateValidation
                && !timeStampValidator.isTimeStampCurrentlyValid(timeStampToken,
                        getTimeStampValidityForTimeStampToken(timeStampToken))) {
            validationInfos.addError("La marca temporale non è attualmente valida");
        }

    }

    /**
     * Effetta l'analisi di un file contenente marche temporali.
     *
     * Il risultato dell'analisi produce una struttura contenente gli esiti dei seguenti controlli:
     * <ul>
     * <li>Riconoscimento del formato di busta</li>
     * <li>Recupero delle marche temporali</li>
     * <li>Individuazione del tipo di marche (detached/embedded)</li>
     * <li>Validazione della corretta associazione tra marca temporale e contenuto firmato</li>
     * <li>Validazione del certificato di timestamp, rispetto:
     * <ul>
     * <li>Alle CRL</li>
     * <li>Alle CA accreditate</li>
     * </ul>
     * </li>
     * <li>Eventuale controllo di validità rispetto alla data corrente</li>
     * </ul>
     *
     * @param file                         busta contenente i timestamp
     * @param executeCurrentDateValidation flag per indicare l'esecuzione della validazione rispetto
     *                                     alla data attuale
     *
     * @return informazioni sulle marche temporali contenute nella busta
     *
     * @throws FileNotFoundException se il file da analizzare non puo' essere recuperato
     * @throws CryptoSignerException se si è verificato un errore durante le fasi di analisi
     */
    public DocumentAndTimeStampInfoBean[] checkTimeStamps(File file,
            boolean executeCurrentDateValidation)
            throws FileNotFoundException, CryptoSignerException {

        List<DocumentAndTimeStampInfoBean> documentAndTimeStampInfoList = new ArrayList<>();

        signer = signerUtil.getSignerManager(file);
        TimeStampToken[] timeStampTokens = signer.getTimeStampTokens();

        if (timeStampTokens != null) {
            for (TimeStampToken timeStampToken : timeStampTokens) {

                DocumentAndTimeStampInfoBean documentAndTimeStampInfo = new DocumentAndTimeStampInfoBean();
                documentAndTimeStampInfo.setAssociatedFile(file);
                documentAndTimeStampInfo.setTimeStampToken(timeStampToken);

                /*
                 * Formato della marca temporale
                 */
                documentAndTimeStampInfo.setProperty(
                        DocumentAndTimeStampInfoBean.PROP_TIMESTAMP_FORMAT, signer.getFormat());

                /*
                 * Tipo di marca (EMBEDDED)
                 */
                documentAndTimeStampInfo.setTimeStampTokenType(
                        DocumentAndTimeStampInfoBean.TimeStampTokenType.EMBEDDED);

                /*
                 * Verifica che la marca temporale corrisponda al file di appartenenza
                 */
                ValidationInfos infos = signer.validateTimeStampTokensEmbedded(timeStampToken);
                if (infos == null) {
                    infos = new ValidationInfos();
                    infos.addWarning(signer.getClass().getName()
                            + " non ha potuto completare la validazione oppure la marca non è di tipo: "
                            + documentAndTimeStampInfo.getTimeStampTokenType());
                }

                /*
                 * Genera gli attributi comuni per tutte le marche temporali
                 */
                populateCommonAttributes(documentAndTimeStampInfo, infos,
                        executeCurrentDateValidation);
                documentAndTimeStampInfo.setValidationInfos(infos);
                documentAndTimeStampInfoList.add(documentAndTimeStampInfo);
            }
        }

        return documentAndTimeStampInfoList
                .toArray(new DocumentAndTimeStampInfoBean[documentAndTimeStampInfoList.size()]);
    }

    /**
     * @see it.eng.crypto.controller.impl.timestamp.TimeStampController#checkTimeStamps(File,
     *      boolean) checkTimeStamps(File,boolean)
     */
    public DocumentAndTimeStampInfoBean[] checkTimeStamps(File file)
            throws FileNotFoundException, CryptoSignerException {
        return checkTimeStamps(file, true);
    }

    /**
     * Effetta l'analisi di un file con marca temporale detached.
     *
     * Il risultato dell'analisi produce una struttura contenente gli esiti dei seguenti controlli:
     * <ul>
     * <li>Riconoscimento del formato di busta</li>
     * <li>Recupero delle marche temporali</li>
     * <li>Individuazione del tipo di marche (detached/embedded)</li>
     * <li>Validazione della corretta associazione tra marca temporale e contenuto firmato</li>
     * <li>Validazione del certificato di timestamp, rispetto:
     * <ul>
     * <li>Alle CRL</li>
     * <li>Alle CA accreditate</li>
     * </ul>
     * </li>
     * <li>Eventuale controllo di validita' rispetto alla data corrente</li>
     * </ul>
     *
     * @param file                         contenuto marcato
     * @param detachedTimeStamp            timestamp associato al contenuto
     * @param executeCurrentDateValidation flag per indicare l'esecuzione della validazione rispetto
     *                                     alla data attuale
     *
     * @return informazioni sulle marche temporali contenute nella busta
     *
     * @throws CryptoSignerException se si è verificato un errore durante le fasi di analisi
     */
    private DocumentAndTimeStampInfoBean[] checkTimeStamps(File file, File detachedTimeStamp,
            boolean executeCurrentDateValidation) throws CryptoSignerException {
        List<DocumentAndTimeStampInfoBean> documentAndTimeStampInfoList = new ArrayList<>();
        signer = signerUtil.getSignerManager(detachedTimeStamp);

        TimeStampToken[] timeStampTokens = signer.getTimeStampTokens();

        if (timeStampTokens != null) {
            for (TimeStampToken timeStampToken : timeStampTokens) {

                DocumentAndTimeStampInfoBean documentAndTimeStampInfo = new DocumentAndTimeStampInfoBean();

                documentAndTimeStampInfo.setAssociatedFile(file);
                documentAndTimeStampInfo.setTimeStampToken(timeStampToken);

                /*
                 * Formato della marca temporale
                 */
                documentAndTimeStampInfo.setProperty(
                        DocumentAndTimeStampInfoBean.PROP_TIMESTAMP_FORMAT, signer.getFormat());

                /*
                 * Tipo di marca (DETACHED)
                 */
                documentAndTimeStampInfo.setTimeStampTokenType(
                        DocumentAndTimeStampInfoBean.TimeStampTokenType.DETACHED);

                /*
                 * Verifica che la marca temporale corrisponda al file di appartenenza
                 */
                ValidationInfos infos = signer.validateTimeStampTokensDetached(file);
                if (infos == null) {
                    infos = new ValidationInfos();
                    infos.addWarning(
                            "Il signer non ha effettuato la validazione oppure la marca non è di tipo: "
                                    + documentAndTimeStampInfo.getTimeStampTokenType());
                }

                /*
                 * Genera gli attributi comuni per tutte le marche temporali
                 */
                populateCommonAttributes(documentAndTimeStampInfo, infos,
                        executeCurrentDateValidation);

                documentAndTimeStampInfo.setValidationInfos(infos);
                documentAndTimeStampInfoList.add(documentAndTimeStampInfo);

            }
        }

        return documentAndTimeStampInfoList
                .toArray(new DocumentAndTimeStampInfoBean[documentAndTimeStampInfoList.size()]);
    }

    /**
     * @see it.eng.crypto.controller.impl.timestamp.TimeStampController#checkTimeStamps(File, File,
     *      boolean) checkTimeStamps(File, File, boolean)
     */
    public DocumentAndTimeStampInfoBean[] checkTimeStamps(File file, File detachedTimeStamp)
            throws FileNotFoundException, CryptoSignerException {
        return checkTimeStamps(file, detachedTimeStamp, true);
    }

    /**
     * Recupera il signer che è stato individuato in seguito all'estrazione del timestamp
     */
    public AbstractSigner getSigner() {
        return signer;
    }

    public void reset() {
        this.signer = null;
    }

    private void checkCRL(ValidationInfos validationInfos, X509Certificate signatureCertificate,
            X509CRL crl, Date date) {
        X509CRLEntry crlEntry = crl.getRevokedCertificate(signatureCertificate);
        // il certificato è stato revocato
        if (crlEntry != null) {
            if (date != null && crlEntry.getRevocationDate().before(date)) {
                validationInfos.addError("Certificato revocato in data: "
                        + crlEntry.getRevocationDate() + " (antecedente a: " + date + ")");
            } else if (date == null) {
                validationInfos.addError(
                        "Certificato già revocato in data: " + crlEntry.getRevocationDate());
            }
        }
    }

    /**
     * @see it.eng.crypto.controller.impl.timestamp.TimeStampController#checkTimeStamps(File,
     *      boolean) checkTimeStamps(File, boolean)
     */
    public DocumentAndTimeStampInfoBean[] checkTimeStamps(File file,
            File... timeStampExtensionChain) throws FileNotFoundException, CryptoSignerException {
        DocumentAndTimeStampInfoBean[] documentAndTimeStampInfos = checkTimeStamps(file, false);
        validateTimeStampsChain(documentAndTimeStampInfos, file, timeStampExtensionChain);
        return documentAndTimeStampInfos;
    }

    /**
     * @see it.eng.crypto.controller.impl.timestamp.TimeStampController#checkTimeStamps(File, File,
     *      boolean) checkTimeStamps(File, File, boolean)
     */
    public DocumentAndTimeStampInfoBean[] checkTimeStamps(File file, File detachedTimeStamp,
            File... timeStampExtensionChain) throws FileNotFoundException, CryptoSignerException {
        DocumentAndTimeStampInfoBean[] documentAndTimeStampInfos = checkTimeStamps(file,
                detachedTimeStamp, false);
        validateTimeStampsChain(documentAndTimeStampInfos, detachedTimeStamp,
                timeStampExtensionChain);
        return documentAndTimeStampInfos;
    }

    /**
     * Recupera la lista dei bean che memorizzano i periodi di validità dei tipi di marche temporali
     *
     * @return
     */
    public List<TimeStampValidityBean> getTimeStampValidity() {
        return timeStampValidity;
    }

    /**
     * Definisce la lista dei bean che memorizzano i periodi di validita' dei tipi di marche
     * temporali
     *
     * @param timeStampValidity
     */
    public void setTimeStampValidity(List<TimeStampValidityBean> timeStampValidity) {
        Arrays.sort((new ArrayList<TimeStampValidityBean>(timeStampValidity)).toArray());
        this.timeStampValidity = timeStampValidity;
    }

    /**
     * Recupera l'istanza del validatore {@link it.eng.crypto.controller.ITimeStampValidator}
     * preposto alla verifica della validità corrente delle marche temporali
     */
    public ITimeStampValidator getTimeStampValidator() {
        return timeStampValidator;
    }

    /**
     * Definisce l'istanza del validatore {@link it.eng.crypto.controller.ITimeStampValidator}
     * preposto alla verifica della validità corrente delle marche temporali
     */
    public void setTimeStampValidator(ITimeStampValidator timeStampValidator) {
        this.timeStampValidator = timeStampValidator;
    }

    private void validateTimeStampsChain(DocumentAndTimeStampInfoBean[] documentAndTimeStampInfos,
            File signedFile, File[] timeStampExtensionChain) throws CryptoSignerException {

        // Controllo se esiste una catena di estensioni del timestamp
        if (timeStampExtensionChain == null) {
            return;
        }

        // Recupero i timestampToken presenti nel documento
        List<TimeStampToken> timeStampTokens = new ArrayList<>();
        for (DocumentAndTimeStampInfoBean documentAndTimeStampInfo : documentAndTimeStampInfos) {
            timeStampTokens.add(documentAndTimeStampInfo.getTimeStampToken());
        }

        TimeStampToken[] currentTimeStampTokens = timeStampTokens
                .toArray(new TimeStampToken[timeStampTokens.size()]);
        File currentFile = signedFile;
        for (int i = 0; i < timeStampExtensionChain.length; ++i) {

            File timeStampExtensionFile = timeStampExtensionChain[i];

            // Recupero il formato..
            AbstractSigner extensionSigner = signerUtil.getSignerManager(timeStampExtensionFile);
            if (extensionSigner != null) {

                // Valido il file detached rispetto al timestamp attuale
                ValidationInfos timeStampTokenExtensionValidation = extensionSigner
                        .validateTimeStampTokensDetached(currentFile);
                if (timeStampTokenExtensionValidation == null
                        || !timeStampTokenExtensionValidation.isValid()) {
                    setAllValidationInfos(documentAndTimeStampInfos, new String[] {
                            "L'estensione della marca temporale #" + (i + 1)
                                    + " contenuta nel file: " + timeStampExtensionFile
                                    + " è invalida per il file: " + currentFile },
                            null);
                    break;
                }

                TimeStampToken[] timeStampExtensions = extensionSigner.getTimeStampTokens();
                if (timeStampExtensions != null && timeStampExtensions.length != 0) {

                    // Aggiungo la lista delle estensioni ai bean di informazioni
                    for (DocumentAndTimeStampInfoBean documentAndTimeStampInfo : documentAndTimeStampInfos) {
                        List<TimeStampToken> timeStampExtensionTokens = documentAndTimeStampInfo
                                .getTimeStampExtensionChain();
                        if (timeStampExtensionTokens == null) {
                            timeStampExtensionTokens = new ArrayList<>();
                            documentAndTimeStampInfo
                                    .setTimeStampExtensionChain(timeStampExtensionTokens);
                        }
                        timeStampExtensionTokens.addAll(Arrays.asList(timeStampExtensions));
                    }

                    // Valido l'estensione del periodo di validita'
                    if (!validateTimeStampExtensionListOverTimeStampList(documentAndTimeStampInfos,
                            currentTimeStampTokens, timeStampExtensions, timeStampExtensionFile,
                            currentFile))
                        break;

                    // Valido la TSA dell'estensione
                    validateTimeStampExtensionListTSA(documentAndTimeStampInfos,
                            timeStampExtensions, timeStampExtensionFile);
                }

                // Verifico l'attuale validita' dell'ultima estensione del timestamp
                if (timeStampExtensions != null && i == timeStampExtensionChain.length - 1) {
                    if (!validateLastTimeStampExtensions(documentAndTimeStampInfos,
                            timeStampExtensions, timeStampExtensionFile))
                        break;
                }

                // Aggiorno il file da validare e la lista dei timeStamp associati
                currentFile = timeStampExtensionFile;
                currentTimeStampTokens = timeStampExtensions;
            }
        }
    }

    private void validateTimeStampExtensionListTSA(
            DocumentAndTimeStampInfoBean[] documentAndTimeStampInfos,
            TimeStampToken[] timeStampExtensions, File timeStampExtensionFile) {
        for (int i = 0; i < timeStampExtensions.length; ++i) {
            TimeStampToken timeStampExtension = timeStampExtensions[i];
            DocumentAndTimeStampInfoBean tmpInfo = new DocumentAndTimeStampInfoBean();
            tmpInfo.setTimeStampToken(timeStampExtension);
            ValidationInfos tmpValidationInfos = new ValidationInfos();
            populateCommonAttributes(tmpInfo, tmpValidationInfos, false);
            if (!tmpValidationInfos.isValid()) {
                setAllValidationInfos(documentAndTimeStampInfos, new String[] {
                        "L'estensione della marca temporale #" + (i + 1) + " contenuta nel file: "
                                + timeStampExtensionFile + " contiene un certificato non valido: "
                                + tmpValidationInfos.getErrors() },
                        null);
            }
            if (tmpValidationInfos.getWarnings() != null
                    && tmpValidationInfos.getWarnings().length != 0) {
                setAllValidationInfos(documentAndTimeStampInfos, null, new String[] {
                        "L'estensione della marca temporale #" + (i + 1) + " contenuta nel file: "
                                + timeStampExtensionFile
                                + " contiene un certificato con il seguente problema: "
                                + tmpValidationInfos.getWarnings() });
            }
        }

    }

    private boolean validateLastTimeStampExtensions(
            DocumentAndTimeStampInfoBean[] documentAndTimeStampInfos,
            TimeStampToken[] timeStampExtensions, File timeStampExtensionFile) {
        boolean result = true;
        for (int i = 0; i < timeStampExtensions.length; ++i) {
            TimeStampToken timeStampExtension = timeStampExtensions[i];
            if (!timeStampValidator.isTimeStampCurrentlyValid(timeStampExtension,
                    getTimeStampValidityForTimeStampToken(timeStampExtension))) {
                setAllValidationInfos(documentAndTimeStampInfos, new String[] {
                        "L'estensione della marca temporale #" + (i + 1) + " contenuta nel file: "
                                + timeStampExtensionFile + " non à correntemente valida" },
                        null);
                result = false;
            }
        }
        return result;
    }

    private boolean validateTimeStampExtensionListOverTimeStampList(
            DocumentAndTimeStampInfoBean[] documentAndTimeStampInfos,
            TimeStampToken[] currentTimeStampTokens, TimeStampToken[] timeStampExtensions,
            File timeStampExtensionFile, File currentFile) {
        boolean result = true;
        for (int i = 0; i < currentTimeStampTokens.length; i++) {
            TimeStampToken currentTimeStampToken = currentTimeStampTokens[i];
            for (int j = 0; j < timeStampExtensions.length; j++) {
                TimeStampToken timeStampExtension = timeStampExtensions[j];
                if (!timeStampValidator.isTimeStampExtended(currentTimeStampToken,
                        getTimeStampValidityForTimeStampToken(currentTimeStampToken),
                        timeStampExtension,
                        getTimeStampValidityForTimeStampToken(timeStampExtension))) {
                    setAllValidationInfos(documentAndTimeStampInfos, new String[] {
                            "L'estensione della marca temporale #" + (j + 1)
                                    + " contenuta nel file: " + timeStampExtensionFile + " ("
                                    + timeStampExtension.getTimeStampInfo().getGenTime() + ")"
                                    + " non estende la marca temporale #" + (i + 1)
                                    + " contenuta nel file: " + currentFile + " ("
                                    + currentTimeStampToken.getTimeStampInfo().getGenTime() + ")" },
                            null);
                    result = false;
                }
            }
        }
        return result;
    }

    private void setAllValidationInfos(DocumentAndTimeStampInfoBean[] documentAndTimeStampInfos,
            String[] errors, String[] warnings) {
        if (documentAndTimeStampInfos == null) {
            return;
        }
        for (DocumentAndTimeStampInfoBean documentAndTimeStampInfo : documentAndTimeStampInfos) {
            if (documentAndTimeStampInfo.getValidationInfos() == null) {
                documentAndTimeStampInfo.setValidationInfos(new ValidationInfos());
            }
            ValidationInfos validationInfos = documentAndTimeStampInfo.getValidationInfos();
            validationInfos.addErrors(errors);
            validationInfos.addWarnings(warnings);
        }
    }

    private TimeStampValidityBean getTimeStampValidityForTimeStampToken(
            TimeStampToken timeStampToken) {
        if (timeStampValidity == null || timeStampValidity.isEmpty()) {
            return null;
        }
        TimeStampValidityBean result = null;
        Iterator<TimeStampValidityBean> iterator = timeStampValidity.iterator();
        Calendar timeStampTokenCalendar = Calendar.getInstance();
        timeStampTokenCalendar.setTime(timeStampToken.getTimeStampInfo().getGenTime());
        Calendar tmpCal = Calendar.getInstance();
        while (iterator.hasNext()) {
            TimeStampValidityBean timeStampValidityBean = iterator.next();
            if (timeStampValidityBean.getBegin() == null) {
                result = timeStampValidityBean;
            } else {
                tmpCal.setTime(timeStampValidityBean.getBegin());
                if (tmpCal.before(timeStampTokenCalendar)) {
                    result = timeStampValidityBean;
                } else {
                    break;
                }
            }
        }
        return result;
    }

}
