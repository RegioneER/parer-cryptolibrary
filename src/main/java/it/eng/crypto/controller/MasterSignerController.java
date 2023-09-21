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

package it.eng.crypto.controller;

import it.eng.crypto.controller.bean.InputSignerBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.data.type.SignerType;
import java.security.cert.CRL;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementa la gestione dei controller. L'analisi viene innescata dalla chiamata al metodo
 * {@link MasterSignerController#executeControll(InputSignerBean)} e iterata su tutti i controller definiti
 * nell'attributo controllers
 *
 * @author Stefano Zennaro
 *
 */
public class MasterSignerController {

    Logger log = LoggerFactory.getLogger(this.getClass().getName());
    // Controller da invocare per l'analisi
    private List<ISignerController> controllers;
    // Mappa dei flag indicanti i controlli da effettuare
    private Map<String, Boolean> checks;
    // Lista delle crl
    private CRL crl;
    // Indica se uno dei controlli bloccanti non è andato a buon fine
    private boolean interrupted = false;

    // Ausiliario
    // private SignerUtil signerUtil = SignerUtil.newInstance();
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
    public OutputSignerBean executeControll(InputSignerBean input) throws ExceptionController {
        OutputSignerBean output = new OutputSignerBean();
        this.execute(input, output);
        return output;
    }

    /**
     * Esegue la sequenza di controlli sul bean di input, iterandoli sul contenuto qualora esso risulti ulteriormente
     * firmato
     *
     */
    private void execute(InputSignerBean input, OutputSignerBean output) throws ExceptionController {
        boolean result;
        input.setChecks(checks);
        input.setCrl(crl);
        for (ISignerController controller : controllers) {
            if (controller.canExecute(input)) {
                try {
                    long start = System.currentTimeMillis();
                    result = controller.execute(input, output);
                    if (!result && controller.isCritical()) {
                        output.setProperty(OutputSignerBean.MASTER_SIGNER_EXCEPTION_PROPERTY,
                                controller.getClass().getName());
                        // Se il signer è TSD è un comportamento normale che il ciclo si sia interrotto: il TSD non ha
                        // firme per cui devo
                        // terminare i controlli sulle firme (quindi eseguire il break) ma non devo settare il flag
                        // interrupted perchè voglio
                        // proseguire le verifiche con lo sbustato
                        if (!input.getSigner().getFormat().equals(SignerType.TSD)) {
                            interrupted = true;
                        }
                        break;
                    }
                    long elapsedTimeMillis = System.currentTimeMillis() - start;
                    log.debug("Controllo: " + controller.getClass().getSimpleName() + " eseguito con successo in "
                            + elapsedTimeMillis + "ms");
                } catch (ExceptionController e) {
                    if (controller.isCritical()) {
                        interrupted = true;
                        output.setProperty(OutputSignerBean.MASTER_SIGNER_EXCEPTION_PROPERTY,
                                controller.getClass().getName());
                        throw e;
                    }
                }

            }
        }

    }

    /**
     * Recupera la mappa dei flag dei controlli
     *
     * @return la mappa dei flag
     */
    public Map<String, Boolean> getChecks() {
        return checks;
    }

    /**
     * Definisce i flag dei controlli da effettuare
     *
     * @param checks
     *            la mappa contenente i flag dei controlli e il loro valore (true/false)
     */
    public void setChecks(Map<String, Boolean> checks) {
        this.checks = checks;
    }

    /**
     * Recupera al CRL configurata e utilizzata nella chiamata al metodo executeControll.
     *
     * @return
     */
    public CRL getCrl() {
        return crl;
    }

    /**
     * Definisce la CRL da utilizzare durante la chiamata al metodo executeControll per verificare la revoca di un
     * certificato
     *
     * @param crl
     */
    public void setCrl(CRL crl) {
        this.crl = crl;
    }

    /**
     * Restituisce lo stato di esecuzione dei controller
     *
     * @return true se uno dei controller ha generato un errore bloccante
     */
    public boolean isInterrupted() {
        return interrupted;
    }

    /**
     * Disabilita i controlli di crittografici di firma
     */
    public void disableCryptoCheck() {
        this.disableCheck("performSignatureAssociation");
    }

    /**
     * Disabilita il controllo di sui certificati di certificazione
     */
    public void disableTrustedChain() {
        this.disableCheck("performCertificateAssociation");
        this.disableCheck("performCertificateReliability");
    }

    /**
     * Disabilita il controllo di scadenza e revoca del certificato del firmatario
     *
     */
    public void disableCertExpAndRevocation() {
        this.disableCheck("performCertificateExpiration");
        this.disableCheck("performCertificateRevocation");
    }

    /**
     * Disabilita un controllo passato come parametro
     *
     */
    private void disableCheck(String checkName) {
        if (checks.containsKey(checkName)) {
            checks.put(checkName, false);
        }
    }
}
