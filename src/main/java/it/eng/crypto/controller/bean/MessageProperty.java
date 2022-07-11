package it.eng.crypto.controller.bean;

public class MessageProperty {

    private String errorContext;

    private int errorCode;

    private String errorMessage;

    /**
     * @return the errorContext
     */
    public String getErrorContext() {
        return errorContext;
    }

    /**
     * @param errorContext
     *            the errorContext to set
     */
    public void setErrorContext(String errorContext) {
        this.errorContext = errorContext;
    }

    /**
     * @return the errorCode
     */
    public int getErrorCode() {
        return errorCode;
    }

    /**
     * @param errorCode
     *            the errorCode to set
     */
    public void setErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }

    /**
     * @return the errorKey
     */
    public String getErrorKey() {
        return errorMessage;
    }

    /**
     * @param errorKey
     *            the errorKey to set
     */
    public void setErrorKey(String errorKey) {
        this.errorMessage = errorKey;
    }

    public String toString() {
        return this.errorMessage;
    }

}
