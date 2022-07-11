package it.eng.crypto.controller;

import it.eng.crypto.controller.bean.InputBean;
import it.eng.crypto.controller.bean.OutputBean;
import it.eng.crypto.controller.exception.ExceptionController;

/**
 * Interfaccia da implementare per i controller di firma di file firmati
 *
 * @author Rigo Michele
 *
 */
public interface ISignerController {

    /**
     * Metodo che consente di verificare se il controllo può essere eseguito a partire dalla attuale configurazione del
     * bean di input
     *
     * @param input
     *            bean contenente le informazioni necessarie all'esecuzione
     * 
     * @return true se il controllo può essere effettuato
     */
    public boolean canExecute(InputBean input);

    /**
     * Esegue il controllo a partire dalle informazioni di input, popolando il bean di output
     *
     * @param input
     *            bean contenente le informazioni necessarie all'esecuzione
     * @param output
     *            bean contenente le proprietà valorizzate dal controller in seguito all'esecuzione
     * 
     * @return true se il controllo è stato superato
     * 
     * @throws ExceptionController
     */
    public boolean execute(InputBean input, OutputBean output) throws ExceptionController;

    /**
     * Restituisce true se il controllo attuale è critico
     *
     * @return
     */
    public boolean isCritical();
}
