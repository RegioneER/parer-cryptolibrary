package it.eng.crypto.controller;

import it.eng.crypto.controller.bean.DocumentAndTimeStampInfoBean;
import it.eng.crypto.controller.bean.InputTimeStampBean;
import it.eng.crypto.controller.bean.OutputTimeStampBean;
import it.eng.crypto.controller.bean.TimeStampValidityBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.controller.exception.ExceptionController;

import java.io.File;
import java.security.Security;
import java.security.cert.CRL;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;

public class MasterTimeStampController {

    // Controller da invocare per l'analisi
    private List<ISignerController> controllers;
    // Mappa dei flag indicanti i controlli da effettuare
    private Map<String, Boolean> checks;
    // Lista delle crl
    private CRL crl;
    // Indica se uno dei controlli bloccanti non è andato a buon fine
    private boolean interrupted = false;
    private ITimeStampValidator timeStampValidator;
    private List<TimeStampValidityBean> timeStampValidity;

    /**
     * Recupera i controller configurati
     *
     * @return i controller configurati
     */
    public List<ISignerController> getControllers() {
        return controllers;
    }

    /**
     * Definisce i controller su cui effettuare l'analisi
     *
     * @param controllers
     *            la lista dei controlli cui cui iterare l'analisi
     */
    public void setControllers(List<ISignerController> controllers) {
        this.controllers = controllers;
    }

    /**
     * Effettua l'analisi richiamando l'esecuzione di ciascun controller configurato.
     *
     * @param input
     *            bean contenente le informazioni in input per eseguire i controlli
     * 
     * @return
     * 
     * @throws ExceptionController
     */
    public OutputTimeStampBean executeControll(InputTimeStampBean input) throws ExceptionController {
        OutputTimeStampBean output = new OutputTimeStampBean();
        this.execute(input, output);
        return output;
    }

    /**
     * Esegue la sequenza di controlli sul bean di input, iterandoli sul contenuto qualora esso risulti ulteriormente
     * firmato
     *
     */
    private void execute(InputTimeStampBean input, OutputTimeStampBean output) throws ExceptionController {
        boolean result;
        input.setChecks(checks);
        input.setCrl(crl);
        for (ISignerController controller : controllers) {
            if (controller.canExecute(input)) {
                try {
                    result = controller.execute(input, output);
                    if (!result && controller.isCritical()) {
                        interrupted = true;
                        break;
                    }
                } catch (ExceptionController e) {
                    if (controller.isCritical()) {
                        interrupted = true;
                        throw e;
                    }
                }
            }
        }

        // Occorre controllare le estensioni delle marche temporali
        // quindi iterare i controlli su ciascuna marca
        checkExtensions(input, output);
    }

    private void checkExtensions(InputTimeStampBean input, OutputTimeStampBean output) throws ExceptionController {

        // Recupero la catena delle estensioni
        File[] timeStampExtensionChain = input.getTimeStampExtensionsChain();
        File timestampFile = input.getTimeStampWithContentFile() == null ? input.getTimeStampFile()
                : input.getTimeStampWithContentFile();

        // if (input.getTimeStampExtensionsChain()!=null){
        // Recupero i timestamp
        List<DocumentAndTimeStampInfoBean> documentAndTimeStampInfos = output.getDocumentAndTimeStampInfos();
        if (documentAndTimeStampInfos == null || documentAndTimeStampInfos.size() == 0) {
            return;
        }

        // Se non ci sono estensioni della marca temporale
        // controllo la validità attuale della marca
        if (timeStampExtensionChain == null || timeStampExtensionChain.length == 0) {
            for (DocumentAndTimeStampInfoBean documentAndTimeStampInfo : documentAndTimeStampInfos) {
                TimeStampToken timeStampToken = documentAndTimeStampInfo.getTimeStampToken();
                ValidationInfos validationInfos = documentAndTimeStampInfo.getValidationInfos();
                TimeStampValidityBean timeStampValidityBean = getTimeStampValidityForTimeStampToken(timeStampToken);
                if (!timeStampValidator.isTimeStampCurrentlyValid(timeStampToken, timeStampValidityBean)) {
                    Date referenceDate = input.getReferenceDate();
                    if (referenceDate == null) {
                        validationInfos.addError("La marca temporale non è attualmente valida");
                    } else {
                        if (timeStampValidator.isTimeStampValidAtDate(timeStampToken, timeStampValidityBean,
                                referenceDate)) {
                            validationInfos.addWarning(
                                    "La marca temporale non è attualmente valida ma è estesa correttamente dalla data di riferimento indicata:"
                                            + referenceDate + ", che ricade nel suo periodo di validità");
                        } else {
                            validationInfos.addError(
                                    "La marca temporale non è attualmente valida e non è estesa dalla data di riferimento indicata: "
                                            + referenceDate);
                        }
                    }
                }
            }
        } // Se ci sono estesioni della marca temporale
          // controllo che siano corrette
        else {
            validateTimeStampsChain(documentAndTimeStampInfos, timestampFile, timeStampExtensionChain);
        }

        // }
    }

    /**
     * @return the timeStampValidator
     */
    public ITimeStampValidator getTimeStampValidator() {
        return timeStampValidator;
    }

    /**
     * @param timeStampValidator
     *            the timeStampValidator to set
     */
    public void setTimeStampValidator(ITimeStampValidator timeStampValidator) {
        this.timeStampValidator = timeStampValidator;
    }

    /**
     * @return the timeStampValidity
     */
    public List<TimeStampValidityBean> getTimeStampValidity() {
        return timeStampValidity;
    }

    /**
     * @param timeStampValidity
     *            the timeStampValidity to set
     */
    public void setTimeStampValidity(List<TimeStampValidityBean> timeStampValidity) {
        this.timeStampValidity = timeStampValidity;
    }

    private TimeStampValidityBean getTimeStampValidityForTimeStampToken(TimeStampToken timeStampToken) {
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

    private void validateTimeStampsChain(List<DocumentAndTimeStampInfoBean> documentAndTimeStampInfos, File signedFile,
            File[] timeStampExtensionChain) throws ExceptionController {

        // Controllo se esiste una catena di estensioni del timestamp
        if (timeStampExtensionChain == null || timeStampExtensionChain.length == 0) {
            return;
        }

        // Recupero i timestampToken presenti nel documento
        List<TimeStampToken> timeStampTokens = new ArrayList<TimeStampToken>();
        for (DocumentAndTimeStampInfoBean documentAndTimeStampInfo : documentAndTimeStampInfos) {
            timeStampTokens.add(documentAndTimeStampInfo.getTimeStampToken());
        }

        // recupero la prima estensione
        File firstExtension = timeStampExtensionChain[0];
        InputTimeStampBean input = new InputTimeStampBean();
        input.setChecks(checks);
        input.setTimeStampFile(firstExtension);
        input.setContentFile(signedFile);

        if (timeStampExtensionChain.length > 1) {
            File[] extensionChainTail = new File[timeStampExtensionChain.length - 1];
            System.arraycopy(timeStampExtensionChain, 1, extensionChainTail, 0, timeStampExtensionChain.length - 1);
            input.setTimeStampExtensionsChain(extensionChainTail);
        }
        try {
            OutputTimeStampBean output = executeControll(input);

            List<DocumentAndTimeStampInfoBean> documentAndTimeStampExtensionInfos = output
                    .getDocumentAndTimeStampInfos();
            if (documentAndTimeStampExtensionInfos == null || documentAndTimeStampExtensionInfos.size() == 0) {
                throw new ExceptionController("L'analisi non ha dato alcun riscontro");
            }

            // Recupero i timestamp presenti nell'estensione della marca
            List<TimeStampToken> timeStampExtensions = new ArrayList<TimeStampToken>();
            for (DocumentAndTimeStampInfoBean documentAndTimeStampExtensionInfo : documentAndTimeStampExtensionInfos) {
                ValidationInfos extensionValidationInfos = documentAndTimeStampExtensionInfo.getValidationInfos();
                if (!extensionValidationInfos.isValid()) {
                    throw new ExceptionController(extensionValidationInfos.toString());
                }
                timeStampExtensions.add(documentAndTimeStampExtensionInfo.getTimeStampToken());
            }
            // Valido l'estensione del periodo di validità
            File timestampFile = input.getTimeStampWithContentFile() == null ? input.getTimeStampFile()
                    : input.getTimeStampWithContentFile();
            validateTimeStampExtensionListOverTimeStampList(documentAndTimeStampInfos, timeStampTokens,
                    timeStampExtensions, firstExtension, timestampFile);
        } catch (ExceptionController e) {
            setAllValidationInfos(documentAndTimeStampInfos,
                    new String[] { "Errore durante l'analisi dell'estensione della marca temporale " + firstExtension
                            + " :" + e.getMessage() },
                    null);
        }
    }

    private boolean validateTimeStampExtensionListOverTimeStampList(
            List<DocumentAndTimeStampInfoBean> documentAndTimeStampInfos, List<TimeStampToken> currentTimeStampTokens,
            List<TimeStampToken> timeStampExtensions, File timeStampExtensionFile, File currentFile) {
        boolean result = true;
        for (int i = 0; i < currentTimeStampTokens.size(); i++) {
            TimeStampToken currentTimeStampToken = currentTimeStampTokens.get(i);
            for (int j = 0; j < timeStampExtensions.size(); j++) {
                TimeStampToken timeStampExtension = timeStampExtensions.get(j);
                if (!timeStampValidator.isTimeStampExtended(currentTimeStampToken,
                        getTimeStampValidityForTimeStampToken(currentTimeStampToken), timeStampExtension,
                        getTimeStampValidityForTimeStampToken(timeStampExtension))) {
                    setAllValidationInfos(documentAndTimeStampInfos,
                            new String[] { "L'estensione della marca temporale #" + (j + 1) + " contenuta nel file: "
                                    + timeStampExtensionFile + " (" + timeStampExtension.getTimeStampInfo().getGenTime()
                                    + ")" + " non estende la marca temporale #" + (i + 1) + " contenuta nel file: "
                                    + currentFile + " (" + currentTimeStampToken.getTimeStampInfo().getGenTime()
                                    + ")" },
                            null);
                    result = false;
                }
            }
        }
        return result;
    }

    private void setAllValidationInfos(List<DocumentAndTimeStampInfoBean> documentAndTimeStampInfos, String[] errors,
            String[] warnings) {
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

    /**
     * @return the checks
     */
    public Map<String, Boolean> getChecks() {
        return checks;
    }

    /**
     * @param checks
     *            the checks to set
     */
    public void setChecks(Map<String, Boolean> checks) {
        this.checks = checks;
    }

    /**
     * @return the crl
     */
    public CRL getCrl() {
        return crl;
    }

    /**
     * @param crl
     *            the crl to set
     */
    public void setCrl(CRL crl) {
        this.crl = crl;
    }

    /**
     * @return the interrupted
     */
    public boolean isInterrupted() {
        return interrupted;
    }
}