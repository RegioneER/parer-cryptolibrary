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

package it.eng.crypto.controller.impl;

import it.eng.crypto.controller.ISignerController;
import it.eng.crypto.controller.bean.InputBean;
import it.eng.crypto.controller.bean.OutputBean;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.data.SignerUtil;

public abstract class AbstractController implements ISignerController {

    /**
     * Indica se il controllo corrente è bloccante (default=false)
     */
    protected boolean critical = false;
    /**
     * Utilità per l'analisi dei formati fi firma
     */
    protected SignerUtil signerUtil = SignerUtil.newInstance();

    /**
     * L'implementazione recupera il flag associato al controller attuale invocando il metodo
     * {@link it.eng.crypto.controller.impl.signature.AbstractSignerController#getCheckProperty}. Se
     * esso è null viene restituito true, altrimenti viene restituito il valore del flag
     */
    @Override
    public boolean canExecute(InputBean input) {
        if (input == null || input.getChecks() == null) {
            return true;
        }
        String checkProperty = getCheckProperty();
        if (checkProperty == null) {
            return true;
        }
        Boolean check = input.getFlag(checkProperty);
        return check == null ? true : check;
    }

    /**
     * Restituisce la chiave da utilizzare per ottenere il nome del flag di esecuzione del filtro.
     * L'implementazione di default restituisce il valore null.
     */
    public String getCheckProperty() {
        return null;
    }

    @Override
    public abstract boolean execute(InputBean input, OutputBean output) throws ExceptionController;

    /**
     * Restituisce true se il controllo è bloccante
     */
    @Override
    public boolean isCritical() {
        return critical;
    }

    /**
     * Definisce se il controllo è bloccante
     *
     * @param critical
     */
    public void setCritical(boolean critical) {
        this.critical = critical;
    }
}
