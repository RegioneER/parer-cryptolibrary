package it.eng.crypto.controller.impl.signature;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import it.eng.crypto.controller.bean.InputSignerBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.data.signature.ISignature;

/**
 * Verifica la corretta associazione tra il contenuto firmato e le firme Per ciascuna firma presente nel
 * {@link it.eng.crypto.controller.bean.InputSignerBean bean di input} viene richiamato il metodo
 * {@link it.eng.crypto.data.signature.ISignature#verify} della firma e salvato il risultato
 */
public class SignatureAssociation extends AbstractSignerController {

    public static final String SIGNATURE_ASSOCIATION_CHECK = "performSignatureAssociation";

    public String getCheckProperty() {
        return SIGNATURE_ASSOCIATION_CHECK;
    }

    public boolean execute(InputSignerBean input, OutputSignerBean output) throws ExceptionController {
        boolean result = true;
        List<ISignature> signatures = null;

        if (output.getProperties().containsKey(OutputSignerBean.SIGNATURE_PROPERTY)) {
            signatures = (List<ISignature>) output.getProperty(OutputSignerBean.SIGNATURE_PROPERTY);
            Map<ISignature, ValidationInfos> validationInfosMap = new HashMap<ISignature, ValidationInfos>();
            result = populateValidationInfosMapFromSignatureList(validationInfosMap, signatures);
            output.setProperty(OutputSignerBean.SIGNATURE_VALIDATION_PROPERTY, validationInfosMap);
        }
        return result;
    }

    private boolean populateValidationInfosMapFromSignatureList(Map<ISignature, ValidationInfos> validationInfosMap,
            List<ISignature> signatures) {
        boolean result = true;
        if (signatures == null || signatures.isEmpty())
            // Perchè la busta sia valida deve esserci almeno una firma
            return false;
        for (ISignature signature : signatures) {

            ValidationInfos validationInfos = signature.verify();

            validationInfosMap.put(signature, validationInfos);
            result &= validationInfos.isValid();
            if (performCounterSignaturesCheck) {
                List<ISignature> counterSignatures = signature.getCounterSignatures();
                populateValidationInfosMapFromSignatureList(validationInfosMap, counterSignatures);
            }

        }
        return result;
    }

}
