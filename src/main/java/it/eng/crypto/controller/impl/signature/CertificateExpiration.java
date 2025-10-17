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

package it.eng.crypto.controller.impl.signature;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import it.eng.crypto.controller.bean.InputSignerBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.data.signature.ISignature;
import it.eng.crypto.utils.VerificheEnums.EsitoControllo;

/**
 * Controlla la validità temporale dei certificati richiamando il metodo checkValidity di ciascun
 * certificato di firma rispetto al riferimento temporale o la data attuale
 *
 * @author Stefano Zennaro
 *
 */
public class CertificateExpiration extends AbstractSignerController {

    /**
     * Proprietà restituita dal metodo
     * {@link it.eng.crypto.controller.impl.signature.CertificateExpiration#getCheckProperty
     * getCheckProperty}
     */
    public static final String CERTIFICATE_EXPIRATION_CHECK = "performCertificateExpiration";

    public String getCheckProperty() {
	return CERTIFICATE_EXPIRATION_CHECK;
    }

    /**
     * L'esecuzione prevede i seguenti passi:
     * <ul>
     * <li>Recupero delle informazioni sul timestamp dal bean di input.</li>
     * <li>Verifica la validità dei certificati di ciascuna firma rispetto alla data del
     * timestamp</li>
     * </ul>
     */
    public boolean execute(InputSignerBean input, OutputSignerBean output)
	    throws ExceptionController {

	boolean result = true;
	Map<ISignature, ValidationInfos> validationInfosMap = new HashMap<ISignature, ValidationInfos>();
	List<ISignature> signatures = null;
	if (output.getProperties().containsKey(OutputSignerBean.SIGNATURE_PROPERTY)) {
	    signatures = (List<ISignature>) output.getProperty(OutputSignerBean.SIGNATURE_PROPERTY);

	    result = populateValidationInfosMapFromSignatureList(validationInfosMap, signatures);
	    output.setProperty(OutputSignerBean.CERTIFICATE_EXPIRATION_PROPERTY,
		    validationInfosMap);
	}

	return result;
    }

    private boolean populateValidationInfosMapFromSignatureList(
	    Map<ISignature, ValidationInfos> validationInfosMap, List<ISignature> signatures) {
	boolean result = true;
	for (ISignature signature : signatures) {

	    ValidationInfos validationInfos = new ValidationInfos();

	    /*
	     * Verifica della validità dei certificati di firma :
	     */
	    X509Certificate signatureCertificate = signature.getSignerBean().getCertificate();

	    /*
	     * Verifico che il certificato sia valido rispetto ai valori di expiration indicati nel
	     * certificato stesso
	     */
	    try {
		if (signature.getReferenceDate() == null) {
		    signatureCertificate.checkValidity();
		} else {
		    signatureCertificate.checkValidity(signature.getReferenceDate());
		}
		validationInfos.setEsito(EsitoControllo.POSITIVO);
	    } catch (CertificateExpiredException e) {

		validationInfos.addError("Il certificato è scaduto in data: "
			+ dateFormatter.format(signatureCertificate.getNotAfter()));
		validationInfos.setEsito(EsitoControllo.CERTIFICATO_SCADUTO);
	    } catch (CertificateNotYetValidException e) {
		validationInfos.addError("Il certificato è valido a partire dalla data: "
			+ dateFormatter.format(signatureCertificate.getNotBefore())
			+ " successiva al riferimento temporale usato: "
			+ dateFormatter.format(signature.getReferenceDate()));
		validationInfos.setEsito(EsitoControllo.CERTIFICATO_NON_VALIDO);
	    }

	    boolean[] keyUsage = signature.getSignerBean().getCertificate().getKeyUsage();
	    if (keyUsage == null || !keyUsage[1]) {
		validationInfos.addError("Il certificato non supporta l'utilizzo non-repudation");
		validationInfos.setEsito(EsitoControllo.CERTIFICATO_ERRATO);
	    }

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
