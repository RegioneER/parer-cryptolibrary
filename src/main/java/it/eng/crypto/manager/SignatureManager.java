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

package it.eng.crypto.manager;

import it.eng.crypto.controller.MasterSignerController;
import it.eng.crypto.controller.MasterTimeStampController;
import it.eng.crypto.controller.bean.DocumentAndTimeStampInfoBean;
import it.eng.crypto.controller.bean.InputSignerBean;
import it.eng.crypto.controller.bean.InputTimeStampBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.bean.OutputTimeStampBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.data.AbstractSigner;
import it.eng.crypto.data.SignerUtil;
import it.eng.crypto.data.signature.ISignature;
import it.eng.crypto.data.type.SignerType;
import it.eng.crypto.exception.CryptoSignerException;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * Definisce il punto di ingresso per l'esecuzione dei controlli sulle firme e marche temporali. <br/>
 * Prevede l'esecuzione dei controlli a partire da 6 possibili configurazioni, corrispondenti ai diversi formati di
 * firma trattati.<br/>
 * Ovvero:
 * <ol>
 * <li><b>Contenuto&Firma</b> - unico file contenente la firma e l'oggetto firmato. Esempio: P7M</li>
 * <li><b>Contenuto&Firma&Timestamp</b> - unico file contenente la firma, l'oggetto firmato e la marca
 * temporale.Esempio: M7M / CaDES / XaDES Embedded</li>
 * <li><b>Contenuto&Firma + Timestamp</b> - 2 file contenenti rispettivamente: la firma con il contenuto firmato, il
 * timestampEsempio: P7M + TSR</li>
 * <li><b>Contenuto + Firma</b> - 2 file contenenti rispettivamente: l'oggetto della firma, la firmaEsempio:
 * fileDetached + P7M</li>
 * <li><b>Contenuto + Firma&TimeStamp</b> - 2 file contenenti rispettivamente: l'oggetto della firma, la firma con il
 * timestampEsempio: fileDetached + M7M / CaDES [/ XaDES] Detached</li>
 * <li><b>Contenuto + Firma + Timestamp</b> - 3 file contenenti rispettivamente: l'oggetto della firma, la firma, il
 * timestampEsempio: fileDetached + P7M + TSR</li>
 * </ol>
 * Le configurazioni precedenti richiedono la valorizzazione dei seguenti attributi:<br>
 * <ul>
 * <li><b>1. & 2.</b> {@link SignatureManager#timeStampedSignatureWithContentFile}</li>
 * <li><b>3.</b> {@link SignatureManager#signatureWithContentFile} + {@link SignatureManager#timeStampFile}</li>
 * <li><b>4. & 5.</b> {@link SignatureManager#detachedContentFile} +
 * {@link SignatureManager#timeStampedSignatureFile}</li>
 * <li><b>6.</b> {@link SignatureManager#detachedContentFile} + {@link SignatureManager#signatureFile} +
 * {@link SignatureManager#timeStampFile}</li>
 * </ul>
 * Questi attributi possono essere valorizzati con la chiamata ai metodi:
 * <ul>
 * <li>{@link SignatureManager#executeEmbedded(File)}</li>
 * <li>{@link SignatureManager#executeEmbedded(File, File)}</li>
 * <li>{@link SignatureManager#executeDetached(File, File)}</li>
 * <li>{@link SignatureManager#executeDetached(File, File, File)}</li>
 * </ul>
 * A ciascuno dei metodi precedenti è associato un metodo aggiuntivo che consente l'analisi di marche temporali di
 * estensione rispetto a quella data:
 * <ul>
 * <li>{@link SignatureManager#executeEmbedded(File, File...)}</li>
 * <li>{@link SignatureManager#executeEmbedded(File, File, File...)}</li>
 * <li>{@link SignatureManager#executeDetached(File, File, File...)}</li>
 * <li>{@link SignatureManager#executeDetached(File, File, File, File...)}</li>
 * </ul>
 * Per evitare ambiguità, i metodi precedenti devono essere richiamati racchiudendo le marche temporali estensive
 * all'interno di un array.<br/>
 * <p>
 * Un diverso approccio per innescare l'esecuzione, prevede l'utilizzo di un bean di configurazione di tipo
 * {@link SignatureManagerConfig} settabile richiamando il metodo
 * {@link SignatureManager#setConfig(SignatureManagerConfig)} oppure direttamente nel metodo
 * {@link execute(SignatureManagerConfig)}.
 * </p>
 * <p>
 * L'esecuzione attiva l'analisi dei file, che può essere suddivisa in 3 fasi:
 * <ol>
 * <li>Estrazione della marca temporale: viene richiamato il filtro di analisi della marca temporale sul file con
 * timestamp embedded o detached</li>
 * <li>Controllo delle firme sulla busta: richiama il {@link MasterSignerController} popolando il bean di input con i
 * dati estratti dalla fase precedente</li>
 * <li>Verifica del contenuto della busta e iterazione dei controlli sulla firma</li>
 * <li>Se il contenuto può essere a sua volta firmato ({@link AbstractSigner#canContentBeSigned
 * signer.canContentBeSigned = true}), viene richiamato il controllo al passo 2, estraendo il contenuto della busta su
 * file e considerando questo come un file di tipo Contenuto&Firma&Timestamp (configurazione 2)</li>
 * </ol>
 * </p>
 *
 * @author Stefano Zennaro
 *
 */
public class SignatureManager {

    MasterTimeStampController masterTimeStampController;
    MasterSignerController masterSignerController;
    /**
     * File contenente l'oggetto della firma
     */
    private File detachedContentFile;
    /**
     * File contenente la firma
     */
    private File signatureFile;
    /**
     * File contenente la firma e l'oggetto della firma
     */
    private File signatureWithContentFile;
    /**
     * File contenente la firma e l'eventuale timestamp
     */
    private File timeStampedSignatureFile;
    /**
     * File contenente il timestamp
     */
    private File timeStampFile;
    /**
     * File contenente la firma, l'oggetto firmato e l'eventuale timestamp
     */
    private File timeStampedSignatureWithContentFile;
    /**
     * Lista dei file corrispondenti alla catena di marche temporali
     */
    private File[] timeStampsChain;
    /**
     * Configurazione del metodo di analisi
     */
    private SignatureManagerConfig config;
    /**
     * Data di riferimento temporale (per la validazione dei certificati di firma)
     */
    private Date referenceDate;
    /**
     * Flag che indica se iterare i controlli sul contenuto sbustato
     */
    private boolean singleStep = false;
    /**
     * Ausiliario per recuperare il signer
     */
    private SignerUtil signerUtil = SignerUtil.newInstance();
    private boolean useSigninTimeAsReferenceDate = false;
    private boolean useExternalReferenceTime = false;
    private boolean useExternalTsdTsrM7MEnvelop = false;
    private String referenceDateType;

    private boolean searchCAOnline;

    private static final ThreadLocal<Boolean> _isXml = new ThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return Boolean.FALSE;
        }
    };

    public OutputTimeStampBean executeMassiveTimeStamp(File timestamp, File[] contentFile) {
        return null;
    }

    /**
     * Avvia l'esecuzione dei controlli a partire dalla configurazione precedentemente definita con la chiamata al
     * metodo {@link SignatureManager#setConfig}
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean execute() throws CryptoSignerException {
        return execute(this.config);
    }

    /**
     * Avvia l'esecuzione dei controlli a partire dalla configurazione passata in ingresso
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean execute(SignatureManagerConfig config) throws CryptoSignerException {
        reset();
        if (config == null || !config.isValid()) {
            throw new CryptoSignerException("Configurazione non valida");
        }
        it.eng.crypto.manager.SignatureManager.CONFIGURATION configuration = config.getConfiguration();
        switch (configuration) {
        case CONFIG_1_2:
            timeStampedSignatureWithContentFile = config.getContentFile();
            break;
        case CONFIG_3:
            signatureWithContentFile = config.getContentFile();
            timeStampFile = config.getTimeStampFile();
            break;
        case CONFIG_4_5:
            detachedContentFile = config.getContentFile();
            timeStampedSignatureFile = config.getSignatureFile();
            break;
        case CONFIG_6:
            detachedContentFile = config.getContentFile();
            signatureFile = config.getSignatureFile();
            timeStampFile = config.getTimeStampFile();
        default:
            break;
        }
        timeStampsChain = config.getTimeStampExtensions();
        this.referenceDate = config.getReferenceDate();
        return run();
    }

    /*
     * #################################################################################### # Modalità di analisi
     * EMBEDDED - unico file contenente firma e contenuto
     */
    /**
     * Avvia l'esecuzione dei controlli su firme embedded con timestamp embedded
     *
     * @param file
     *            contenente firma, contenuto firmato ed eventuale marca temporale
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeEmbedded(File timeStampedSignatureWithContentFile) throws CryptoSignerException {
        return executeEmbedded(timeStampedSignatureWithContentFile, (Date) null);
    }

    /**
     * Avvia l'esecuzione dei controlli su firme embedded con timestamp detached
     *
     * @param signatureWithContentFile
     *            firma e contenuto firmato
     * @param timeStampFile
     *            marca temporale detached
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeEmbedded(File signatureWithContentFile, File timeStampFile)
            throws CryptoSignerException {
        return executeEmbedded(signatureWithContentFile, timeStampFile, (Date) null);
    }

    /**
     * Avvia l'esecuzione dei controlli su firme embedded e marche embedded, eseguendo la validazione della catena di
     * estensioni della marca temporale
     *
     * @param timeStampedSignatureWithContentFile
     *            file contenente firma, contenuto firmato ed eventuale marca temporale
     * @param timeStampExtensionFiles
     *            catena di estensioni della marca temporale
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeEmbedded(File timeStampedSignatureWithContentFile, File... timeStampExtensionFiles)
            throws CryptoSignerException {
        return executeEmbedded(timeStampedSignatureWithContentFile, (Date) null, timeStampExtensionFiles);
    }

    /**
     * Avvia l'esecuzione dei controlli su firme embedded con timestamp detached, eseguendo la validazione della catena
     * di estensioni della marca temporale
     *
     * @param signatureWithContentFile
     *            file contenente firma e contenuto firmato
     * @param timeStampFile
     *            marca temporale detached
     * @param timeStampExtensionFiles
     *            catena di estensioni della marca temporale
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeEmbedded(File signatureWithContentFile, File timeStampFile,
            File... timeStampExtensionFiles) throws CryptoSignerException {
        return executeEmbedded(signatureWithContentFile, timeStampFile, (Date) null, timeStampExtensionFiles);
    }

    /**
     * Avvia l'esecuzione dei controlli su firme embedded con timestamp embedded
     *
     * @param file
     *            contenente firma, contenuto firmato ed eventuale marca temporale
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeEmbedded(File timeStampedSignatureWithContentFile, Date reference)
            throws CryptoSignerException {
        reset();
        this.timeStampedSignatureWithContentFile = timeStampedSignatureWithContentFile;
        this.referenceDate = reference;
        return run();
    }

    /**
     * Avvia l'esecuzione dei controlli su firme embedded con timestamp detached
     *
     * @param signatureWithContentFile
     *            firma e contenuto firmato
     * @param timeStampFile
     *            marca temporale detached
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeEmbedded(File signatureWithContentFile, Date reference, File timeStampFile)
            throws CryptoSignerException {
        reset();
        this.signatureWithContentFile = signatureWithContentFile;
        this.timeStampFile = timeStampFile;
        this.referenceDate = reference;
        return run();
    }

    /**
     * Avvia l'esecuzione dei controlli su firme embedded e marche embedded, eseguendo la validazione della catena di
     * estensioni della marca temporale
     *
     * @param timeStampedSignatureWithContentFile
     *            file contenente firma, contenuto firmato ed eventuale marca temporale
     * @param timeStampExtensionFiles
     *            catena di estensioni della marca temporale
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeEmbedded(File timeStampedSignatureWithContentFile, Date reference,
            File... timeStampExtensionFiles) throws CryptoSignerException {
        reset();
        this.timeStampedSignatureWithContentFile = timeStampedSignatureWithContentFile;
        this.timeStampsChain = timeStampExtensionFiles;
        this.referenceDate = reference;
        return run();
    }

    /**
     * Avvia l'esecuzione dei controlli su firme embedded con timestamp detached, eseguendo la validazione della catena
     * di estensioni della marca temporale
     *
     * @param signatureWithContentFile
     *            file contenente firma e contenuto firmato
     * @param timeStampFile
     *            marca temporale detached
     * @param timeStampExtensionFiles
     *            catena di estensioni della marca temporale
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeEmbedded(File signatureWithContentFile, File timeStampFile, Date reference,
            File... timeStampExtensionFiles) throws CryptoSignerException {
        reset();
        this.signatureWithContentFile = signatureWithContentFile;
        this.timeStampFile = timeStampFile;
        this.timeStampsChain = timeStampExtensionFiles;
        this.referenceDate = reference;
        return run();
    }

    /*
     * #################################################################################### # Modalità di analisi
     * DETACHED - un file per la firma e uno per contenuto
     */
    /**
     * Avvia l'esecuzione dei controlli su firme detached
     *
     * @param detachedContentFile
     *            contenuto firmato
     * @param timeStampedSignatureFile
     *            firma digitale con eventuale marca temporale
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeDetached(File detachedContentFile, File timeStampedSignatureFile)
            throws CryptoSignerException {
        return executeDetached(detachedContentFile, timeStampedSignatureFile, (Date) null);
    }

    /**
     * Avvia l'esecuzione dei controlli su firme detached con timestamp detached
     *
     * @param detachedContentFile
     *            contenuto firmato
     * @param signatureFile
     *            firma digitale
     * @param timeStampFile
     *            marca temporale
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeDetached(File detachedContentFile, File signatureFile, File timeStampFile)
            throws CryptoSignerException {
        return executeDetached(detachedContentFile, signatureFile, timeStampFile, (Date) null);
    }

    /**
     * Avvia l'esecuzione dei controlli su firme detached, eseguendo la validazione della catena di estensioni della
     * marca temporale
     *
     * @param detachedContentFile
     *            contenuto firmato
     * @param timeStampedSignatureFile
     *            firma digitale con eventuale marca temporale
     * @param timeStampExtensionFiles
     *            catena di estensioni della marca temporale
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeDetached(File detachedContentFile, File timeStampedSignatureFile,
            File... timeStampExtensionFiles) throws CryptoSignerException {
        return executeDetached(detachedContentFile, timeStampedSignatureFile, (Date) null, timeStampExtensionFiles);
    }

    /**
     * Avvia l'esecuzione dei controlli su firme detached con timestamp detached, eseguendo la validazione della catena
     * di estensioni della marca temporale
     *
     * @param detachedContentFile
     *            contenuto firmato
     * @param signatureFile
     *            firma digitale
     * @param timeStampFile
     *            marca temporale
     * @param timeStampExtensionFiles
     *            catena di estensioni della marca temporale
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeDetached(File detachedContentFile, File signatureFile, File timeStampFile,
            File... timeStampExtensionFiles) throws CryptoSignerException {
        return executeDetached(detachedContentFile, signatureFile, timeStampFile, (Date) null, timeStampExtensionFiles);
    }

    /**
     * Avvia l'esecuzione dei controlli su firme detached
     *
     * @param detachedContentFile
     *            contenuto firmato
     * @param timeStampedSignatureFile
     *            firma digitale con eventuale marca temporale
     * @param reference
     *            data di riferimento temporale
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeDetached(File detachedContentFile, File timeStampedSignatureFile, Date reference)
            throws CryptoSignerException {
        reset();
        this.detachedContentFile = detachedContentFile;
        this.timeStampedSignatureFile = timeStampedSignatureFile;
        this.referenceDate = reference;
        return run();
    }

    /**
     * Avvia l'esecuzione dei controlli su firme detached con timestamp detached
     *
     * @param detachedContentFile
     *            contenuto firmato
     * @param signatureFile
     *            firma digitale
     * @param timeStampFile
     *            marca temporale
     * @param reference
     *            data di riferimento temporale
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeDetached(File detachedContentFile, File signatureFile, File timeStampFile,
            Date reference) throws CryptoSignerException {
        reset();
        this.detachedContentFile = detachedContentFile;
        this.signatureFile = signatureFile;
        this.timeStampFile = timeStampFile;
        this.referenceDate = reference;
        return run();
    }

    /**
     * Avvia l'esecuzione dei controlli su firme detached, eseguendo la validazione della catena di estensioni della
     * marca temporale
     *
     * @param detachedContentFile
     *            contenuto firmato
     * @param timeStampedSignatureFile
     *            firma digitale con eventuale marca temporale
     * @param timeStampExtensionFiles
     *            catena di estensioni della marca temporale
     * @param reference
     *            data di riferimento temporale
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeDetached(File detachedContentFile, File timeStampedSignatureFile, Date reference,
            File... timeStampExtensionFiles) throws CryptoSignerException {
        reset();
        this.detachedContentFile = detachedContentFile;
        this.timeStampedSignatureFile = timeStampedSignatureFile;
        this.timeStampsChain = timeStampExtensionFiles;
        this.referenceDate = reference;
        return run();
    }

    /**
     * Avvia l'esecuzione dei controlli su firme detached con timestamp detached, eseguendo la validazione della catena
     * di estensioni della marca temporale
     *
     * @param detachedContentFile
     *            contenuto firmato
     * @param signatureFile
     *            firma digitale
     * @param timeStampFile
     *            marca temporale
     * @param timeStampExtensionFiles
     *            catena di estensioni della marca temporale
     * @param reference
     *            data di riferimento temporale
     *
     * @return bean di output contenente i risultati dell'analisi
     *
     * @throws CryptoSignerException
     */
    public OutputSignerBean executeDetached(File detachedContentFile, File signatureFile, File timeStampFile,
            Date reference, File... timeStampExtensionFiles) throws CryptoSignerException {
        reset();
        this.detachedContentFile = detachedContentFile;
        this.signatureFile = signatureFile;
        this.timeStampFile = timeStampFile;
        this.timeStampsChain = timeStampExtensionFiles;
        this.referenceDate = reference;
        return run();
    }

    private void reset() {
        this.detachedContentFile = null;
        this.signatureFile = null;
        this.timeStampFile = null;
        this.timeStampedSignatureFile = null;
        this.timeStampsChain = null;
        this.signatureWithContentFile = null;
        this.timeStampedSignatureWithContentFile = null;
        this.referenceDate = null;
    }

    private OutputSignerBean run() {

        CONFIGURATION configuration = getConfiguration();

        // Esegue il primo ciclo di controllo
        OutputSignerBean outputSigner = executeCycle(configuration, referenceDate);

        // Se si vuole eseguire il controllo anche sul contenuto sbustato
        if (!singleStep) {

            // Esegue il controllo sul contenuto sbustato
            OutputSignerBean currentOutput = outputSigner;
            while (currentOutput != null && currentOutput.getContent() != null
                    && currentOutput.getContent().isPossiblySigned()) {
                // Verifico se il controllo precedente si è interrotto
                // a causa di un errore di un controllo bloccante
                if (masterSignerController.isInterrupted()) {
                    break;
                } else {
                    timeStampedSignatureWithContentFile = currentOutput.getContent().getContentFile();
                    // Ottengo la marca temporale: valida, più vecchia e non Embedded (ie: detached, embedded_m7m e
                    // embedded_tsd)
                    DocumentAndTimeStampInfoBean oldestTS = getTimeStampDateFromOutput(currentOutput);
                    Date newReference = oldestTS == null ? null
                            : oldestTS.getTimeStampToken().getTimeStampInfo().getGenTime();
                    // Setto il riferimento solo se non devo utilizzare un riferimento esterno più prioritario (CHIUSURA
                    // VOLUMI)
                    if (oldestTS != null && !useExternalReferenceTime) {
                        useExternalTsdTsrM7MEnvelop = true;
                        referenceDate = newReference;
                    }

                    OutputSignerBean tmpOutput = executeCycle(CONFIGURATION.CONFIG_1_2, newReference);
                    if (tmpOutput == null) {
                        break;
                    }
                    currentOutput.setChild(tmpOutput);
                    currentOutput = currentOutput.getChild();
                }
            }

        }
        return outputSigner;
    }

    private OutputSignerBean executeCycle(CONFIGURATION configuration, Date reference) {
        OutputTimeStampBean outputTimeStamp = getDocumentAndTimeStampInfos(configuration, reference);
        OutputSignerBean outputSigner = getOutputSigner(configuration, outputTimeStamp);
        return outputSigner;
    }

    /**
     * ************************************************ Controllo del timestamp
     */
    public OutputTimeStampBean getDocumentAndTimeStampInfos(CONFIGURATION configuration, Date reference) {

        if (masterTimeStampController == null) {
            return null;
        }

        InputTimeStampBean input = new InputTimeStampBean();
        OutputTimeStampBean output = null;
        try {

            switch (configuration) {

            case CONFIG_1_2:
                input.setTimeStampWithContentFile(timeStampedSignatureWithContentFile);
                break;

            case CONFIG_3:
                input.setTimeStampFile(timeStampFile);
                input.setContentFile(signatureWithContentFile);
                break;

            case CONFIG_4_5:
                input.setTimeStampWithContentFile(timeStampedSignatureFile);
                break;

            case CONFIG_6:
                input.setTimeStampFile(timeStampFile);
                input.setContentFile(signatureFile);
                break;

            default:
                break;
            }

            input.setReferenceDate(reference);
            input.setTimeStampExtensionsChain(timeStampsChain);
            output = masterTimeStampController.executeControll(input);

        } catch (ExceptionController e) {
            // e.printStackTrace();
            // Questa eccezione può essere generata solo se il signer non è stato trovato, recupero il check di
            // Validazione, poi,
            // nel controllo di fime (getOutputSigner) imposterò l'outputTimeStamp nuovamente a null
            if (e.getComplianceChecks() != null) {
                output = new OutputTimeStampBean();
                output.setComplianceChecks(e.getComplianceChecks());
            }
        }
        return output;
    }

    /**
     * ************************************************ Controllo delle firme
     */
    public OutputSignerBean getOutputSigner(CONFIGURATION configuration, OutputTimeStampBean outputTimeStamp) {
        AbstractSigner signer = null;
        InputSignerBean input = new InputSignerBean();
        input.setCheckCAOnline(isSearchCAOnline());
        Map<String, ValidationInfos> complianceChecks = null;
        if (outputTimeStamp != null && outputTimeStamp.getComplianceChecks() != null) {
            complianceChecks = outputTimeStamp.getComplianceChecks();
            outputTimeStamp = null;
        }
        File envelope = null;
        try {

            switch (configuration) {
            case CONFIG_1_2:
                signer = outputTimeStamp == null ? null : outputTimeStamp.getSigner();
                envelope = timeStampedSignatureWithContentFile;
                break;

            case CONFIG_3:
                signer = signerUtil.getSignerManager(signatureWithContentFile);
                envelope = signatureWithContentFile;
                break;

            case CONFIG_4_5:
                signer = outputTimeStamp == null ? null : outputTimeStamp.getSigner();
                envelope = timeStampedSignatureFile;
                if (signer != null) {
                    signer.setDetachedFile(detachedContentFile);
                }
                break;

            case CONFIG_6:
                signer = signerUtil.getSignerManager(signatureFile);
                envelope = signatureFile;
                if (signer != null) {
                    signer.setDetachedFile(detachedContentFile);
                }
                break;

            default:
                break;
            }

        } catch (CryptoSignerException e) {
            complianceChecks = e.getComplianceChecks();
            if (signer != null) {
                e.printStackTrace();
            }
        }

        List<DocumentAndTimeStampInfoBean> timeStampInfos = outputTimeStamp == null ? null
                : outputTimeStamp.getDocumentAndTimeStampInfos();
        OutputSignerBean output = null;
        // Se il contenuto non è firmato oppure il file è un TSR ritorno i soli dati sul timestamp (qualora presenti)
        if (signer == null || signer.getFormat().equals(SignerType.TSR)) {
            output = new OutputSignerBean();
            output.setProperty(OutputSignerBean.FORMAT_COMPLIANCE_PROPERTY, complianceChecks);
            if (timeStampInfos == null) {
                if (complianceChecks == null) {
                    return null;
                }
                return output;
            }
            output.setProperty(OutputSignerBean.TIME_STAMP_INFO_PROPERTY, timeStampInfos);
            return output;
        }

        // Mantengo solo i timestamp che sono validi
        List<DocumentAndTimeStampInfoBean> validTimeStampInfosList = new ArrayList<DocumentAndTimeStampInfoBean>();
        if (timeStampInfos != null && !timeStampInfos.isEmpty()) {
            for (DocumentAndTimeStampInfoBean timeStampInfo : timeStampInfos) {
                if (timeStampInfo.getValidationInfos().isValid()) {
                    validTimeStampInfosList.add(timeStampInfo);
                }
            }
        }

        List<DocumentAndTimeStampInfoBean> detachedValidTimeStampInfosList = new ArrayList<DocumentAndTimeStampInfoBean>();
        for (DocumentAndTimeStampInfoBean timeStampInfo : validTimeStampInfosList) {
            if (timeStampInfo.getTimeStampTokenType().equals(DocumentAndTimeStampInfoBean.TimeStampTokenType.DETACHED)
                    || timeStampInfo.getTimeStampTokenType()
                            .equals(DocumentAndTimeStampInfoBean.TimeStampTokenType.EMBEDDED_M7M)
                    || timeStampInfo.getTimeStampTokenType()
                            .equals(DocumentAndTimeStampInfoBean.TimeStampTokenType.EMBEDDED_TSD)) {
                detachedValidTimeStampInfosList.add(timeStampInfo);
            }
        }

        // Popolo il bean di input
        input.setUseExternalReferenceTime(this.useExternalReferenceTime);
        input.setUseExternalTsdTsrM7MEnvelop(this.useExternalTsdTsrM7MEnvelop);
        input.setEnvelope(envelope);
        input.setUseSigninTimeAsReferenceDate(this.useSigninTimeAsReferenceDate);
        input.setReferenceDateType(this.referenceDateType);

        // Cerco il più vecchio timestamp DETACHED
        DocumentAndTimeStampInfoBean oldest = null;
        if (detachedValidTimeStampInfosList != null && !detachedValidTimeStampInfosList.isEmpty()) {
            oldest = getOldestDocumentAndTimeStampInfoBean(detachedValidTimeStampInfosList);
            input.setDocumentAndTimeStampInfo(oldest);
        }
        input.setValidTimeStampInfo(validTimeStampInfosList);

        input.setSigner(signer);

        /*
         * Il settaggio della data di riferimento temporale è effettuata per singola firma. Ad occuparsene, quindi, sarà
         * il controller SignatureExtraction che lo setterà in ogni firma. Per avere un comportamento corretto il
         * controllo SignatureExtraction deve essere effettuato prima degli altri I riferimenti temporali utilizzabili
         * per firma sono (partendo dal più prioritario): - Un eventuale TSD presente nella busta esterna - La Marca
         * detached più vecchia tra le detached se valida(da usare quindi per tutte le firme presenti) - Marca embedded
         * se valida(da usare per la firma a cui si riferisce) - Data di firma (da usare per la firma a cui si
         * riferisce) - Data passata da chi chiama il metodo - Data attuale
         */

        if (referenceDate != null) {
            input.setReferenceDate(referenceDate);
        } else {
            referenceDate = new Date();
            input.setReferenceDate(referenceDate);
        }
        try {
            output = masterSignerController.executeControll(input);
        } catch (ExceptionController e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        output.setProperty(OutputSignerBean.TIME_STAMP_INFO_PROPERTY, timeStampInfos);
        return output;
    }

    /*
     * Recupera il controller preposto alla gestione dei cicli di analisi sui file firmati
     *
     * @return l'istanza del controller preposto alla gestione dei cicli di analisi sui file firmati
     */
    public MasterSignerController getMasterSignerController() {
        return masterSignerController;
    }

    /**
     * Definisce il il controller preposto alla gestione dei cicli di analisi sui file firmati
     *
     * @param masterSignerController
     */
    public void setMasterSignerController(MasterSignerController masterSignerController) {
        this.masterSignerController = masterSignerController;
    }

    protected CONFIGURATION getConfiguration() {
        if (timeStampedSignatureWithContentFile != null) {
            return CONFIGURATION.CONFIG_1_2;
        } else if (signatureWithContentFile != null && timeStampFile != null) {
            return CONFIGURATION.CONFIG_3;
        } else if (detachedContentFile != null && timeStampedSignatureFile != null) {
            return CONFIGURATION.CONFIG_4_5;
        } else if (detachedContentFile != null && signatureFile != null && timeStampFile != null) {
            return CONFIGURATION.CONFIG_6;
        }
        return null;
    }

    enum CONFIGURATION {

        CONFIG_1_2, CONFIG_3, CONFIG_4_5, CONFIG_6
    }

    /**
     * Recupera la configurazione su cui eseguire le operazioni di analisi
     *
     * @return
     */
    public SignatureManagerConfig getConfig() {
        return config;
    }

    /**
     * Definisce la configurazione su cui eseguire le operazioni di analisi
     *
     * @param config
     */
    public void setConfig(SignatureManagerConfig config) {
        this.config = config;
    }

    private DocumentAndTimeStampInfoBean getOldestDocumentAndTimeStampInfoBean(
            List<DocumentAndTimeStampInfoBean> timeStampInfos) {
        if (timeStampInfos == null || timeStampInfos.isEmpty()) {
            return null;
        }
        DocumentAndTimeStampInfoBean oldest = timeStampInfos.get(0);
        for (DocumentAndTimeStampInfoBean timeStampInfo : timeStampInfos) {
            if (oldest.getTimeStampToken().getTimeStampInfo().getGenTime()
                    .after(timeStampInfo.getTimeStampToken().getTimeStampInfo().getGenTime())) {
                oldest = timeStampInfo;
            }
        }
        return oldest;
    }

    private DocumentAndTimeStampInfoBean getTimeStampDateFromOutput(OutputSignerBean outputSignerBean) {
        List<DocumentAndTimeStampInfoBean> timeStampInfos = (List<DocumentAndTimeStampInfoBean>) outputSignerBean
                .getProperty(OutputSignerBean.TIME_STAMP_INFO_PROPERTY);
        ArrayList<DocumentAndTimeStampInfoBean> validTimeStampInfosList = new ArrayList<DocumentAndTimeStampInfoBean>();
        if (timeStampInfos != null && !timeStampInfos.isEmpty()) {
            for (DocumentAndTimeStampInfoBean timeStampInfo : timeStampInfos) {
                if (timeStampInfo.getValidationInfos().isValid() && !timeStampInfo.getTimeStampTokenType()
                        .equals(DocumentAndTimeStampInfoBean.TimeStampTokenType.EMBEDDED)) {
                    validTimeStampInfosList.add(timeStampInfo);
                }
            }
        }
        DocumentAndTimeStampInfoBean documentAndTimeStampInfoBean = getOldestDocumentAndTimeStampInfoBean(
                validTimeStampInfosList);
        return documentAndTimeStampInfoBean;// == null ? null :
                                            // documentAndTimeStampInfoBean.getTimeStampToken().getTimeStampInfo().getGenTime();
    }

    /**
     * @return the referenceDate
     */
    public Date getReferenceDate() {
        return referenceDate;
    }

    /**
     * @param referenceDate
     *            the referenceDate to set
     */
    public void setReferenceDate(Date referenceDate) {
        this.referenceDate = referenceDate;
    }

    /**
     * @return the masterTimeStampController
     */
    public MasterTimeStampController getMasterTimeStampController() {
        return masterTimeStampController;
    }

    /**
     * @param masterTimeStampController
     *            the masterTimeStampController to set
     */
    public void setMasterTimeStampController(MasterTimeStampController masterTimeStampController) {
        this.masterTimeStampController = masterTimeStampController;
    }

    /**
     * @return the singleStep
     */
    public boolean isSingleStep() {
        return singleStep;
    }

    /**
     * @param singleStep
     *            the singleStep to set
     */
    public void setSingleStep(boolean singleStep) {
        this.singleStep = singleStep;
    }

    /**
     *
     * @see it.eng.crypto.controller.MasterSignerController#disableCryptoCheck()
     */
    public void disableCryptoCheck() {
        masterSignerController.disableCryptoCheck();
    }

    /**
     *
     * @see it.eng.crypto.controller.MasterSignerController#disableTrustedChain()
     */
    public void disableTrustedChain() {
        masterSignerController.disableTrustedChain();
    }

    /**
     *
     * @see it.eng.crypto.controller.MasterSignerController#disableCertExpAndRevocation()
     */
    public void disableCertExpAndRevocation() {
        masterSignerController.disableCertExpAndRevocation();
    }

    public boolean isUseSigninTimeAsReferenceDate() {
        return useSigninTimeAsReferenceDate;
    }

    public void setUseSigninTimeAsReferenceDate(boolean useSigninTimeAsReferenceDate) {
        this.useSigninTimeAsReferenceDate = useSigninTimeAsReferenceDate;
    }

    public String getReferenceDateType() {
        return referenceDateType;
    }

    public void setReferenceDateType(String referenceDateType) {
        this.referenceDateType = referenceDateType;
    }

    public boolean isUseExternalReferenceTime() {
        return useExternalReferenceTime;
    }

    public void setUseExternalReferenceTime(boolean useExternalReferenceTime) {
        this.useExternalReferenceTime = useExternalReferenceTime;
    }

    public boolean isSearchCAOnline() {
        return searchCAOnline;
    }

    public void setSearchCAOnline(boolean searchCAOnline) {
        this.searchCAOnline = searchCAOnline;
    }

    public static Boolean getIsXml() {
        return _isXml.get();
    }

    public static void setIsXml(Boolean isXml) {
        _isXml.set(isXml);
    }

    public static void cleanIsXml() {
        _isXml.remove();
    }
}
