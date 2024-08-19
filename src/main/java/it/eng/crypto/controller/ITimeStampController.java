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

package it.eng.crypto.controller;

import java.io.File;
import java.io.FileNotFoundException;

import it.eng.crypto.controller.bean.DocumentAndTimeStampInfoBean;
import it.eng.crypto.data.AbstractSigner;
import it.eng.crypto.exception.CryptoSignerException;

/**
 * Definisce l'interfaccia di un controller preposto alle attività di analisi, verifica e validazione di marche
 * temporali embedded o detached.
 *
 * @author Stefano Zennaro
 */
public interface ITimeStampController {

    /**
     * Controlla e restituisce le informazioni riguardo alle marche temporali presenti in un di un file
     *
     * @param file
     *            file contenente il documento e la marca temporale
     *
     * @return informazioni relative alla marca temporale
     *
     * @throws FileNotFoundException
     * @throws CryptoSignerException
     */
    /**
     * Controlla e restituisce le informazioni riguardo alle marche temporali presenti in un file, verificando la
     * validità della lista di estensioni di marche temporali passate in ingresso.
     *
     * @param file
     *            file contenente il documento e la marca temporale
     *
     * @return informazioni relative alla marca temporale
     *
     * @throws FileNotFoundException
     * @throws CryptoSignerException
     */
    public DocumentAndTimeStampInfoBean[] checkTimeStamps(File file)
            throws FileNotFoundException, CryptoSignerException;

    /**
     * Controlla e restituisce le informazioni riguardo alla marca temporale di un file, verificando la validità della
     * lista delle estensioni
     *
     * @param file
     *            file contenente il documento e la marca temporale
     * @param timeStampExtensionChain
     *            lista dei timestamp che estendono le marche temporali
     *
     * @return informazioni relative alle marche temporali
     *
     * @throws FileNotFoundException
     * @throws CryptoSignerException
     */
    public DocumentAndTimeStampInfoBean[] checkTimeStamps(File file, File... timeStampExtensionChain)
            throws FileNotFoundException, CryptoSignerException;

    /**
     * Controlla e restituisce le informazioni riguardo alle marche temporali presenti in un file detached
     *
     * @param file
     *            file contenente il documento
     * @param detachedTimeStamp
     *            file contente la marca temporale del documento
     *
     * @return informazioni relative alle marche temporali
     *
     * @throws CryptoSignerException
     * @throws FileNotFoundException
     */
    public DocumentAndTimeStampInfoBean[] checkTimeStamps(File file, File detachedTimeStamp)
            throws FileNotFoundException, CryptoSignerException;

    /**
     * Controlla e restituisce le informazioni riguardo alle marche temporali presenti in un file detached, verificando
     * la validità della lista delle estensioni verificando la validità della lista delle estensioni
     *
     * @param file
     *            file contenente il documento
     * @param detachedTimeStamp
     *            file contente le marche temporali del documento
     * @param timeStampExtensionChain
     *            lista dei timestamp che estendono le marche temporali
     *
     * @return informazioni relative alle marche temporali
     *
     * @throws FileNotFoundException
     * @throws CryptoSignerException
     */
    public DocumentAndTimeStampInfoBean[] checkTimeStamps(File file, File detachedTimeStamp,
            File... timeStampExtensionChain) throws FileNotFoundException, CryptoSignerException;

    /**
     * Recupera il {@link it.eng.crypto.data.AbstractSigner signer} utilizzato per l'analisi e verifica delle marche
     * temporali in seguito alla chiamata a un metodo check
     *
     * @return il signer delle marche temporali
     */
    public AbstractSigner getSigner();

    /**
     * Resetta lo stato interno del controller successivamente alla chiamata ad un metodo check Può essere richiama
     */
    public void reset();

    /**
     * Recupara il validatore temporale delle marche
     *
     * @return il validatore
     */
    public ITimeStampValidator getTimeStampValidator();

    /**
     * Definisce l'istanza preposta al controllo della validità temporale delle marche
     *
     * @param timeStampValidator
     *            validatore temporale delle marche
     */
    public void setTimeStampValidator(ITimeStampValidator timeStampValidator);
}
