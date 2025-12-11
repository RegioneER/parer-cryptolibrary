/*
 * Engineering Ingegneria Informatica S.p.A.
 *
 * Copyright (C) 2023 Regione Emilia-Romagna <p/> This program is free software: you can
 * redistribute it and/or modify it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version. <p/> This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Affero General Public License for more details. <p/> You should
 * have received a copy of the GNU Affero General Public License along with this program. If not,
 * see <https://www.gnu.org/licenses/>.
 */

package it.eng.crypto.storage;

import it.eng.crypto.exception.CryptoStorageException;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.x500.X500Principal;

/**
 * Storage dei certificati
 *
 * @author Rigo Michele
 *
 * @version 0.1
 */
public interface ICAStorage {

    /**
     * Inserisco una nuovo Certificato se esiste già viene sovrascritto
     *
     * @param certificate
     */
    public void insertCA(X509Certificate certificate) throws CryptoStorageException;

    /**
     * Recupero il certificato dal soggetto X500Principal, se non trova il certificato restituisce
     * null.
     *
     * @param subject
     *
     * @return X509Certificate
     */
    public X509Certificate retriveCA(X500Principal subject, String authorityKeyId)
            throws CryptoStorageException;

    ;

    /**
     * Restituisce la lista dei certificati attivi.
     *
     * @param subject
     *
     * @return
     */
    public List<X509Certificate> retriveActiveCA() throws CryptoStorageException;

    /**
     * Controlla se il certificato è ancora attivo
     *
     * @param certificate
     */
    public boolean isActive(X509Certificate certificate, String authorityKeyId)
            throws CryptoStorageException;
}
