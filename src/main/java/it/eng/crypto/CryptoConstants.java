package it.eng.crypto;

/**
 * Costanti del sistema
 *
 * @author Rigo Michele
 * 
 * @version 0.1
 */
public class CryptoConstants {

    /**
     * Identificativo del bean di configurazione
     */
    public static final String CRYPTO_CONFIGURATION = "CryptoConfiguration";
    /**
     * Identificativo dello storage per il salvataggio delle Certification Authorities
     */
    public static final String ICASTORAGE = "CAStorage";
    /**
     * Identificativo dello storage per il salvataggio delle CRL
     */
    public static final String ICRLSTORAGE = "CRLStorage";
    /**
     * Identificativo dello storage per il salvataggio delle CRL
     */
    public static final String ICONFIGSTORAGE = "ConfigStorage";
    /**
     * Identificativo dello storage per il salvataggio delle configurazioni dei task
     */
    public static final String ICERTIFICATEAUTHORITY = "CertificateAuthorityUpdate";
    /**
     * Identificativo del task adibito all'aggiornamento delle certification authorities
     */
    public static final String CA_UPDATE_TASK = "CA_UPDATE_TASK";
    /**
     * Identificativo del task adibito alla revoca delle certification authorities
     */
    public static final String CA_REVOKE_TASK = "CA_REVOKE_TASK";
}