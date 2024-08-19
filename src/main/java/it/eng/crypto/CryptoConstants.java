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
