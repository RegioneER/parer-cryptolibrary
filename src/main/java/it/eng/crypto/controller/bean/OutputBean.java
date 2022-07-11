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
