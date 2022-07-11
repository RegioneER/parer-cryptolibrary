package it.eng.crypto.exception;

/**
 * Eccezione specializzata per lo storage
 *
 * @author Rigo Michele
 * 
 * @verison 0.1 14/04/2010
 */
public class CryptoStorageException extends Exception {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public CryptoStorageException() {
        super();
    }

    public CryptoStorageException(String arg0, Throwable arg1) {
        super(arg0, arg1);
    }

    public CryptoStorageException(String arg0) {
        super(arg0);
    }

    public CryptoStorageException(Throwable arg0) {
        super(arg0);
    }
}