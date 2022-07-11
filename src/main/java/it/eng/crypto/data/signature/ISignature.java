package it.eng.crypto.data.signature;

import java.util.List;

import it.eng.crypto.bean.SignerBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.data.type.SignerType;
import java.util.Date;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * Definisce l'interfaccia per la descrizione di una firma digitale omologando i diversi formati e implementazioni,
 * garantendo un accesso comune alle operazioni di verifica ed estrazione del contenuto
 * 
 * @author Stefano Zennaro
 *
 */
public interface ISignature {

    /**
     * Recupera la firma digitale sotto forma di array doi byte
     * 
     * @return il valore in bytes della firma digitale
     */
    public byte[] getSignatureBytes();

    /**
     * Recupera il bean contenente le informazioni sulla la firma digitale
     * 
     * @return il bean contenente le informazioni sulla firma digitale
     */
    public SignerBean getSignerBean();

    /**
     * Recupera la data delle firme se presente
     * 
     * @return la lista delle controfirme
     */
    public Date getDateSignature();

    /**
     * Recupera la data della marca associata alla firma
     * 
     * @return la lista delle controfirme
     */
    public TimeStampToken getTimeStamp();

    /**
     * Recupera la data da usare come riferimento temporale
     * 
     * @return la lista delle controfirme
     */
    public Date getReferenceDate();

    /**
     * Recupera la data da usare come riferimento temporale
     * 
     * @return la lista delle controfirme
     */
    public void setReferenceDate(Date referenceDate);

    /**
     * Effettua la verifica della firma digitale
     * 
     * @return il bean contenente le informazioni sull'esito della verifica
     */
    public ValidationInfos verify();

    /**
     * Recupera la lista delle controfirme
     * 
     * @return la lista delle controfirme
     */
    public List<ISignature> getCounterSignatures();

    public String getSigAlgorithm();

    public String getReferenceDateType();

    public void setReferenceDateType(String referenceDateType);

    public void setFormatoFirma(SignerType formatoFirma);

    public SignerType getFormatoFirma();

    // public String getSigHashAlg();

}
