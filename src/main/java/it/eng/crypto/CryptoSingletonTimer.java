package it.eng.crypto;

import org.springframework.context.ApplicationContext;

/**
 * Definisce il singleton che si occupa della configurazione del CryptoSigner in termini di:
 * <ul>
 * <li>Task schedulati</li>
 * <li>Componenti definiti nel contesto Spring</li>
 * </ul>
 *
 * @author Michele Rigo
 *
 */
public class CryptoSingletonTimer {

    private CryptoSingletonTimer() {
    }

    private static CryptoSingletonTimer singleton = null;

    public static synchronized CryptoSingletonTimer getInstance() {
        if (singleton == null) {
            singleton = new CryptoSingletonTimer();
        }
        return singleton;
    }

    /**
     * Application Context di spring per la cofigurazione
     */
    private ApplicationContext context;

    /**
     * Recupera il bean di configurazione configurato nel contesto spring
     *
     * @return
     */
    public CryptoConfiguration getConfiguration() {
        return context.getBean(CryptoConstants.CRYPTO_CONFIGURATION, CryptoConfiguration.class);
    }

    /**
     * Definisce l'application context di spring per la cofigurazione
     *
     * @param context
     */
    public void setContext(ApplicationContext context) {
        this.context = context;
    }

    /**
     * Recupera l'Application Context di spring per la cofigurazione
     *
     * @return
     */
    protected ApplicationContext getContext() {
        return this.context;
    }
}