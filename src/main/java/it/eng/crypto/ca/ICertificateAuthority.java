package it.eng.crypto.ca;

import it.eng.crypto.exception.CryptoSignerException;

/**
 * Espone i metodi di gestione della certification authority root
 *
 * @author Rigo Michele
 * 
 * @version 0.1
 */
public interface ICertificateAuthority {

    /**
     * Effettua l'update dei certificati validi dal sito del CNIPA
     *
     * @throws CryptoSignerException
     */
    public void updateCertificate() throws CryptoSignerException;

    /**
     * Controlla se i certificati ancora attivi sono stati revocati
     *
     * @throws CryptoSignerException
     */
    public void revokeControll() throws CryptoSignerException;
}