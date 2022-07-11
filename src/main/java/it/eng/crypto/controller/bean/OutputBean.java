package it.eng.crypto.controller.bean;

import java.util.HashMap;
import java.util.Map;

public class OutputBean {

    private Map<String, Object> properties = new HashMap<String, Object>();

    private OutputSignerBean child;

    /**
     * Recupera una proprietà settata nel bean
     * 
     * @param key
     *            nome della proprietà da recuperare
     * 
     * @return valore della proprietà
     */
    public Object getProperty(String key) {
        return properties.get(key);
    }

    /**
     * Definisce il valore di una proprietà del bean
     * 
     * @param key
     *            nome della proprietà
     * @param value
     *            valore della proprietà
     */
    public void setProperty(String key, Object value) {
        properties.put(key, value);
    }

    /**
     * Recupera tutte le proprietà settate nel bean
     * 
     * @return la mappa tra i nomi e i valori delle proprietà
     */
    public Map<String, Object> getProperties() {
        return properties;
    }

    /**
     * Definisce le proprietà del bean
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
