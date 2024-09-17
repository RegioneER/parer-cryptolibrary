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

package it.eng.crypto.storage;

import java.math.BigDecimal;
import java.util.List;

import it.eng.crypto.bean.ConfigBean;
import it.eng.crypto.exception.CryptoStorageException;

/**
 * Espone i metodi di salvataggio e recupero delle configurazione dei task
 *
 * @author Rigo Michele
 *
 * @version 0.1
 */
public interface IConfigStorage {

    /**
     * Inserisce e sovrascrive la nuova configurazione se esiste.
     */
    public void upsertConfig(ConfigBean config) throws CryptoStorageException;

    /**
     * Recupera la configurazione esistente per subjectDN.
     *
     * @param subjectDN
     *
     * @return
     */
    public ConfigBean retriveConfig(String subjectDN, String keyId, BigDecimal numOrdine) throws CryptoStorageException;

    /**
     * Elimina la configurazione in base al subjectDN.
     *
     * @param subjectDN
     */
    public void deleteConfig(String subjectDN, String keyId, BigDecimal numOrdine) throws CryptoStorageException;

    /**
     * Recupera la configurazione esistente per subjectDN.
     *
     * @param subjectDN
     *
     * @return
     */
    public List<ConfigBean> retriveAllConfig() throws CryptoStorageException;
}
