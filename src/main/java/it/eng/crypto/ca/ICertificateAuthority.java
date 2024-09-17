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

package it.eng.crypto.ca;

import it.eng.crypto.exception.CryptoSignerException;

/**
 * Espone i metodi di gestione della certification authority root
 *
 * @author Rigo Michele
 *
 * @version 0.1
 */
public interface ICertificateAuthority {

    /**
     * Effettua l'update dei certificati validi dal sito del CNIPA
     *
     * @throws CryptoSignerException
     */
    public void updateCertificate() throws CryptoSignerException;

    /**
     * Controlla se i certificati ancora attivi sono stati revocati
     *
     * @throws CryptoSignerException
     */
    public void revokeControll() throws CryptoSignerException;
}
