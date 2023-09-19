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

package it.eng.crypto.controller.bean;

import java.util.HashMap;
import java.util.Map;

public class OutputBean {

    private Map<String, Object> properties = new HashMap<String, Object>();

    private OutputSignerBean child;

    /**
     * Recupera una propriet� settata nel bean
     * 
     * @param key
     *            nome della propriet� da recuperare
     * 
     * @return valore della propriet�
     */
    public Object getProperty(String key) {
        return properties.get(key);
    }

    /**
     * Definisce il valore di una propriet� del bean
     * 
     * @param key
     *            nome della propriet�
     * @param value
     *            valore della propriet�
     */
    public void setProperty(String key, Object value) {
        properties.put(key, value);
    }

    /**
     * Recupera tutte le propriet� settate nel bean
     * 
     * @return la mappa tra i nomi e i valori delle propriet�
     */
    public Map<String, Object> getProperties() {
        return properties;
    }

    /**
     * Definisce le propriet� del bean
     * 
     * @param properties
     */
    public void setProperties(Map<String, Object> properties) {
        this.properties = properties;
    }

    /**
     * Recupera l'istanza dell'{@link it.eng.crypto.controller.bean.OutputSignerBean OutputSignerBean} linkato
     * (contenente il risultato del successivo ciclo di analisi)
     * 
     * @return
     */
    public OutputSignerBean getChild() {
        return child;
    }

    /**
     * Definisce l'istanza dell'{@link it.eng.crypto.controller.bean.OutputSignerBean OutputSignerBean} linkato
     * (contenente il risultato del successivo ciclo di analisi)
     * 
     * @return
     */
    public void setChild(OutputSignerBean child) {
        this.child = child;
    }

    public String toString() {
        return "Properties: " + properties == null ? "" : properties.toString();
    }

}
