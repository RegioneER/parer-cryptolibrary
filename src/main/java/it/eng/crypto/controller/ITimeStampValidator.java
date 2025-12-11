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

package it.eng.crypto.controller;

import java.util.Date;

import it.eng.crypto.controller.bean.TimeStampValidityBean;

import org.bouncycastle.tsp.TimeStampToken;

/**
 * Definisce l'interfaccia di una classe che implementa i controlli sulla validità temporale di una
 * marca.
 *
 * @author Stefano Zennaro
 *
 */
public interface ITimeStampValidator {

    /**
     * Controlla se il timeStamp in input è attualmente valido rispetto al periodo di validità
     * specificato in input. Una tipica implementazione prevede il recupero della data attuale da
     * una fonte attendibile e successivamente il suo confronto con la data riportata nella marca
     * temporale tenendo in considerazione il periodo di validità.
     *
     * @param timeStamp
     * @param timeStampValidity
     *
     * @return true se la marca temporale in input è attualmente valida
     */
    public boolean isTimeStampCurrentlyValid(TimeStampToken timeStamp,
            TimeStampValidityBean timeStampValidity);

    /**
     * Controlla se il periodo di validità di un timestamp è esteso correttamente da un ulteriore
     * timestamp.<br/>
     * Attenzione: il controllo di corretta associazione tra tra il timestamp e la sue estensione
     * non è previsto e deve essere implementato a parte.
     *
     * @param timeStampToValidate         timestamp su cui validare l'estensione
     * @param timeStampToValidateValidity periodo di validità del timestamp da validare
     * @param timeStampExtension          estensione del timestamp
     * @param timeStampExtensionValidity  periodo di validità dell'estensione del timestamp
     *
     * @return
     */
    public boolean isTimeStampExtended(TimeStampToken timeStampToValidate,
            TimeStampValidityBean timeStampToValidateValidity, TimeStampToken timeStampExtension,
            TimeStampValidityBean timeStampExtensionValidity);

    /**
     * Controlla se il timestamp in input era valido nella data specificata rispetto al suo periodo
     * di validità. Verifica cioè se il riferimento temporale ricade nel periodo di validità del
     * timestamp
     *
     * @param timeStamp         timestamp da validare
     * @param timeStampValidity periodo di validità del timestamp
     * @param referenceDate     data di riferimento
     *
     * @return
     */
    public boolean isTimeStampValidAtDate(TimeStampToken timeStamp,
            TimeStampValidityBean timeStampValidity, Date referenceDate);
}
