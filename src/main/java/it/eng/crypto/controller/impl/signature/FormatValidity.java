package it.eng.crypto.controller.impl.signature;

import it.eng.crypto.controller.bean.InputSignerBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.data.signature.ISignature;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.bouncycastle.cms.CMSSignedDataGenerator;

/**
 * Effettua due tipi di controlli:
 * <ul>
 * <li>Recupera il formato della busta tramite la chiamata al metodo {@link it.eng.crypto.data.AbstractSigner#getFormat
 * getFormat} del signer dalla busta,</li>
 * <li>Confronta l’eventuale riferimento temporale configurata nel bena di input con la data di validità configurata nel
 * campo validityProperties</li>
 * </ul>
 *
 * @author Administrator
 *
 */
public class FormatValidity extends AbstractSignerController {

    /**
     * Proprietà restituita dal metodo
     * {@link it.eng.crypto.controller.impl.signature.CertificateReliability#getCheckProperty getCheckProperty}
     */
    public static final String FORMAT_VALIDITY_CHECK = "performFormatValidity";

    public String getCheckProperty() {
        return FORMAT_VALIDITY_CHECK;
    }

    private Properties validityProperties;
    private DateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");

    /**
     * Recupera i periodi di validità associati a ciascun formato di firma
     *
     * @return
     */
    public Properties getValidityProperties() {
        return validityProperties;
    }

    /**
     * Definisce i periodi di validità di ciascun formato di firma
     *
     * @param validityProperties
     */
    public void setValidityProperties(Properties validityProperties) {
        this.validityProperties = validityProperties;
    }

    /**
     * Recupera il formato di data utilizzato per indicare i periodi di validità
     *
     * @return
     */
    public DateFormat getDateFormat() {
        return dateFormat;
    }

    /**
     * Definisce il formato di data utilizzato per indicare i periodi di validità
     *
     * @return
     */
    public void setDateFormat(DateFormat dateFormat) {
        this.dateFormat = dateFormat;
    }

    public boolean execute(InputSignerBean input, OutputSignerBean output) throws ExceptionController {

        // DONE ! - TODO Forse da spostare per ogni firma, da verificare ... Setto il formato della busta
        output.setProperty(OutputSignerBean.ENVELOPE_FORMAT_PROPERTY, input.getSigner().getFormat().toString());

        boolean result = true;

        // DONE ! Sposto la verifica del formato per singola firma
        // String format = input.getSigner().getFormat().toString();
        // String validity = validityProperties.getProperty(format);

        // DocumentAndTimeStampInfoBean timeStampInfo= input.getDocumentAndTimeStampInfo();
        // recupero il riferimento temporale dal timestamptoken

        List<ISignature> signatures = null;
        if (output.getProperties().containsKey(OutputSignerBean.SIGNATURE_PROPERTY)) {
            signatures = (List<ISignature>) output.getProperty(OutputSignerBean.SIGNATURE_PROPERTY);
            Map<ISignature, ValidationInfos> validationInfosMap = new HashMap<ISignature, ValidationInfos>();
            result = populateValidationInfosMapFromSignatureList(validationInfosMap, signatures);
            output.setProperty(OutputSignerBean.FORMAT_VALIDITY_PROPERTY, validationInfosMap);
        }
        return result;

    }

    private boolean populateValidationInfosMapFromSignatureList(Map<ISignature, ValidationInfos> validationInfosMap,
            List<ISignature> signatures) {
        boolean result = true;
        if (signatures == null || signatures.size() == 0) // Perchè la busta sia valida deve esserci almeno una firma
        {
            return false;
        }

        for (ISignature signature : signatures) {
            // Verifica del formato per singola firma
            // Verifico che la firma non si MD5, in tal caso non valida
            if (signature.getSigAlgorithm() != null && signature.getSigAlgorithm().startsWith("MD5")) {
                ValidationInfos validationInfos = new ValidationInfos();
                validationInfos
                        .addError("L'algoritmo di firma non è valido. Gli algoritmi ammessi sono SHA-1 o SHA-256");
                result = false;
                validationInfosMap.put(signature, validationInfos);
            } else {
                String validity = validityProperties.getProperty(signature.getFormatoFirma().name());
                if (validity != null) {
                    ValidationInfos validationInfos = new ValidationInfos();
                    try {
                        Date date = dateFormat.parse(validity);
                        if (date.before(signature.getReferenceDate())) {
                            validationInfos.addError(
                                    "Il formato di firma utilizzato è scaduto in data " + dateFormatter.format(date)
                                            + ", antecedente al riferimento temporale considerato: "
                                            + dateFormatter.format(signature.getReferenceDate()));
                            result = false;
                        }
                    } catch (ParseException e) {
                        e.printStackTrace();
                        validationInfos.addError(
                                "Non è stato possibile verificare la scadenza della data, poichè il formato della data non è riconosciuto: "
                                        + dateFormatter.format(validity));
                        result = false;
                    }
                    validationInfosMap.put(signature, validationInfos);
                }
            }
            if (performCounterSignaturesCheck) {
                List<ISignature> counterSignatures = signature.getCounterSignatures();
                populateValidationInfosMapFromSignatureList(validationInfosMap, counterSignatures);
            }
        }
        return result;
    }
}
