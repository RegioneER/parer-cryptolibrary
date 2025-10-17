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
     * Metodo che consente di verificare se il controllo può essere eseguito a partire dalla attuale
     * configurazione del bean di input
     *
     * @param input bean contenente le informazioni necessarie all'esecuzione
     *
     * @return true se il controllo può essere effettuato
     */
    public boolean canExecute(InputBean input);

    /**
     * Esegue il controllo a partire dalle informazioni di input, popolando il bean di output
     *
     * @param input  bean contenente le informazioni necessarie all'esecuzione
     * @param output bean contenente le propriet� valorizzate dal controller in seguito
     *               all'esecuzione
     *
     * @return true se il controllo � stato superato
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
