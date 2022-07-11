package it.eng.crypto.storage;

import it.eng.crypto.exception.CryptoStorageException;

import java.security.cert.X509CRL;

/**
 * Storage delle CRL
 *
 * @author Rigo Michele
 * 
 * @version 0.1
 */
public interface ICRLStorage {

    /**
     * Inserico una CRL nello storage associata ad un certificato
     *
     * @param crl
     */
    public void upsertCRL(X509CRL crl) throws CryptoStorageException;

    /**
     * Recupero la CRL dal certificato
     *
     * @param crl
     * 
     * @return
     */
    public X509CRL retriveCRL(String subjectDN, String keyId) throws CryptoStorageException;
}
