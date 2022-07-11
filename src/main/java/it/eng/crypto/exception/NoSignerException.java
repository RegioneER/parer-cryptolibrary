package it.eng.crypto.exception;

/**
 * Eccezione specializzata per il mancato recupero della classe Signer
 *
 * @author Rigo Michele
 * 
 * @verison 0.1 14/04/2010
 */
public class NoSignerException extends Exception {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public NoSignerException() {
        super();
        // TODO Auto-generated constructor stub
    }

    public NoSignerException(String message, Throwable cause) {
        super(message, cause);
        // TODO Auto-generated constructor stub
    }

    public NoSignerException(String message) {
        super(message);
        // TODO Auto-generated constructor stub
    }

    public NoSignerException(Throwable cause) {
        super(cause);
        // TODO Auto-generated constructor stub
    }
}
