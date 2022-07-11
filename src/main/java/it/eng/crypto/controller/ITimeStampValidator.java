package it.eng.crypto.controller;

import java.util.Date;

import it.eng.crypto.controller.bean.TimeStampValidityBean;

import org.bouncycastle.tsp.TimeStampToken;

/**
 * Definisce l'interfaccia di una classe che implementa i controlli sulla validit� temporale di una marca.
 *
 * @author Stefano Zennaro
 *
 */
public interface ITimeStampValidator {

    /**
     * Controlla se il timeStamp in input � attualmente valido rispetto al periodo di validit� specificato in input. Una
     * tipica implementazione prevede il recupero della data attuale da una fonte attendibile e successivamente il suo
     * confronto con la data riportata nella marca temporale tenendo in considerazione il periodo di validit�.
     *
     * @param timeStamp
     * @param timeStampValidity
     * 
     * @return true se la marca temporale in input � attualmente valida
     */
    public boolean isTimeStampCurrentlyValid(TimeStampToken timeStamp, TimeStampValidityBean timeStampValidity);

    /**
     * Controlla se il periodo di validit� di un timestamp � esteso correttamente da un ulteriore timestamp.<br/>
     * Attenzione: il controllo di corretta associazione tra tra il timestamp e la sue estensione non � previsto e deve
     * essere implementato a parte.
     *
     * @param timeStampToValidate
     *            timestamp su cui validare l'estensione
     * @param timeStampToValidateValidity
     *            periodo di validit� del timestamp da validare
     * @param timeStampExtension
     *            estensione del timestamp
     * @param timeStampExtensionValidity
     *            periodo di validit� dell'estensione del timestamp
     * 
     * @return
     */
    public boolean isTimeStampExtended(TimeStampToken timeStampToValidate,
            TimeStampValidityBean timeStampToValidateValidity, TimeStampToken timeStampExtension,
            TimeStampValidityBean timeStampExtensionValidity);

    /**
     * Controlla se il timestamp in input era valido nella data specificata rispetto al suo periodo di validit�.
     * Verifica cio� se il riferimento temporale ricade nel periodo di validit� del timestamp
     *
     * @param timeStamp
     *            timestamp da validare
     * @param timeStampValidity
     *            periodo di validit� del timestamp
     * @param referenceDate
     *            data di riferimento
     * 
     * @return
     */
    public boolean isTimeStampValidAtDate(TimeStampToken timeStamp, TimeStampValidityBean timeStampValidity,
            Date referenceDate);
}
