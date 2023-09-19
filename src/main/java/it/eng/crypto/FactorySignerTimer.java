/*
 * Engineering Ingegneria Informatica S.p.A.
 *
 * Copyright (C) 2023 Regione Emilia-Romagna
 * <p/>
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Affero General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 * <p/>
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package it.eng.crypto;

import it.eng.crypto.ca.ICertificateAuthority;
import it.eng.crypto.context.CryptoSignerApplicationContextProvider;
import it.eng.crypto.exception.CryptoSignerException;
import it.eng.crypto.storage.ICAStorage;
import it.eng.crypto.storage.ICRLStorage;
import it.eng.crypto.storage.IConfigStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.ApplicationContext;

/**
 * Classe che definisce la logica di business preposta alle operazioni di registrazione e monitoraggio dei task
 *
 * @author Michele Rigo
 *
 */
public class FactorySignerTimer {

    static Logger log = LoggerFactory.getLogger(FactorySignerTimer.class);
    /*
     * Stringa utilizzata per sincronizzare i metodi di start stop.
     */
    private static String synchronize = "SINC";

    /**
     * Registra l'ApplicationContext di Spring per il recupero delle configurazioni
     *
     * @param configuration
     */
    public static void registerSpringContext(ApplicationContext context) {
        CryptoSingletonTimer.getInstance().setContext(context);
    }

    /**
     * Avvia i task di aggiornamento dei certificati delle CA
     *
     * @throws CryptoSignerException
     */
    public static void initialize() throws CryptoSignerException {
        synchronized (synchronize) {
            if (CryptoSingletonTimer.getInstance().getContext() == null) {
                ApplicationContext context = CryptoSignerApplicationContextProvider.getContext();
                registerSpringContext(context);
            }
            getInstanceCertificateAuthority().updateCertificate();
        }
    }

    public static void setup() throws CryptoSignerException {

        initialize();
    }

    /**
     * Restiruisce un'istanza dello storage delle CA
     *
     * @return
     */
    public static synchronized ICAStorage getInstanceCAStorage() {
        return CryptoSingletonTimer.getInstance().getContext().getBean(CryptoConstants.ICASTORAGE, ICAStorage.class);
    }

    /**
     * Restituisce un'istanza dello storage delle CRL
     *
     * @return
     */
    public static synchronized ICRLStorage getInstanceCRLStorage() {
        return CryptoSingletonTimer.getInstance().getContext().getBean(CryptoConstants.ICRLSTORAGE, ICRLStorage.class);
    }

    /**
     * Restituisce un'istanza dello storage della CONFIG
     *
     * @return
     */
    public static synchronized IConfigStorage getInstanceConfigStorage() {
        return CryptoSingletonTimer.getInstance().getContext().getBean(CryptoConstants.ICONFIGSTORAGE,
                IConfigStorage.class);
    }

    /**
     * Restituisce un'istanza dello storage della CONFIG
     *
     * @return
     */
    public static synchronized ICertificateAuthority getInstanceCertificateAuthority() {
        return CryptoSingletonTimer.getInstance().getContext().getBean(CryptoConstants.ICERTIFICATEAUTHORITY,
                ICertificateAuthority.class);
    }
}
