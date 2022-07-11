package it.eng.crypto.storage;

import java.math.BigDecimal;
import java.util.List;

import it.eng.crypto.bean.ConfigBean;
import it.eng.crypto.exception.CryptoStorageException;

/**
 * Espone i metodi di salvataggio e recupero delle configurazione dei task
 *
 * @author Rigo Michele
 * 
 * @version 0.1
 */
public interface IConfigStorage {

    /**
     * Inserisce e sovrascrive la nuova configurazione se esiste.
     */
    public void upsertConfig(ConfigBean config) throws CryptoStorageException;

    /**
     * Recupera la configurazione esistente per subjectDN.
     *
     * @param subjectDN
     * 
     * @return
     */
    public ConfigBean retriveConfig(String subjectDN, String keyId, BigDecimal numOrdine) throws CryptoStorageException;

    /**
     * Elimina la configurazione in base al subjectDN.
     *
     * @param subjectDN
     */
    public void deleteConfig(String subjectDN, String keyId, BigDecimal numOrdine) throws CryptoStorageException;

    /**
     * Recupera la configurazione esistente per subjectDN.
     *
     * @param subjectDN
     * 
     * @return
     */
    public List<ConfigBean> retriveAllConfig() throws CryptoStorageException;
}