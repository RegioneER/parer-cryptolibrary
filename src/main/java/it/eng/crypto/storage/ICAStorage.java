package it.eng.crypto.storage;

import it.eng.crypto.exception.CryptoStorageException;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.x500.X500Principal;

/**
 * Storage dei certificati
 *
 * @author Rigo Michele
 * 
 * @version 0.1
 */
public interface ICAStorage {

    /**
     * Inserisco una nuovo Certificato se esiste già viene sovrascritto
     *
     * @param certificate
     */
    public void insertCA(X509Certificate certificate) throws CryptoStorageException;

    /**
     * Recupero il certificato dal soggetto X500Principal, se non trova il certificato restituisce null.
     *
     * @param subject
     * 
     * @return X509Certificate
     */
    public X509Certificate retriveCA(X500Principal subject, String authorityKeyId) throws CryptoStorageException;

    ;

    /**
     * Restituisce la lista dei certificati attivi.
     * 
     * @param subject
     * 
     * @return
     */
    public List<X509Certificate> retriveActiveCA() throws CryptoStorageException;

    /**
     * Controlla se il certificato è ancora attivo
     *
     * @param certificate
     */
    public boolean isActive(X509Certificate certificate, String authorityKeyId) throws CryptoStorageException;
}