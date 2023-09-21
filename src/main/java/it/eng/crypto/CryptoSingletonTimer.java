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
