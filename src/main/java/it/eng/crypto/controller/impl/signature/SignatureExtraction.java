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

import java.util.List;

import org.bouncycastle.tsp.TimeStampToken;

import it.eng.crypto.controller.bean.DocumentAndTimeStampInfoBean;
import it.eng.crypto.controller.bean.InputSignerBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.data.AbstractSigner;
import it.eng.crypto.data.signature.ISignature;
import it.eng.crypto.utils.VerificheEnums.TipoRifTemporale;

/**
 * Recupera il contenuto della busta tramite la chiamata al metodo
 * {@link it.eng.crypto.data.AbstractSigner#getContentAsFile getContentAsFile} del signer ad esso
 * associato.
 *
 * @author Stefano Zennaro
 *
 */
public class SignatureExtraction extends AbstractSignerController {

    private boolean useSigninTimeAsReferenceDate;

    public boolean execute(InputSignerBean input, OutputSignerBean output)
	    throws ExceptionController {
	AbstractSigner signer = input.getSigner();
	List<ISignature> signatures = signer.getSignatures();

	// Il settaggio della data di riferimento temporale è effettuata per singola firma.
	// I riferimenti temporali utilizzabili per firma sono (partendo dal meno prioritario):
	this.setReferenceDate(signatures, input);
	output.setProperty(OutputSignerBean.SIGNATURE_PROPERTY, signatures);
	return signatures != null && !signatures.isEmpty();
    }

    public boolean isUseSigninTimeAsReferenceDate() {
	return useSigninTimeAsReferenceDate;
    }

    public void setUseSigninTimeAsReferenceDate(boolean useSigninTimeAsReferenceDate) {
	this.useSigninTimeAsReferenceDate = useSigninTimeAsReferenceDate;
    }

    private void setReferenceDate(List<ISignature> signatures, InputSignerBean input) {
	if (signatures != null) {
	    for (ISignature s : signatures) {

		// 0 - Riferimento temporale ESTERNO PASSATO (CASO DELLA CHIUSURA DEI VOLUMI - Il
		// paramentro è settato
		// nel contesto xml spring)
		if (input.getUseExternalReferenceTime().booleanValue()) {
		    s.setReferenceDate(input.getReferenceDate());
		} else {
		    TimeStampToken tst = null;
		    for (DocumentAndTimeStampInfoBean d : input.getValidTimeStampInfo()) {
			if (d.equals(s.getTimeStamp())) {
			    tst = s.getTimeStamp();
			    break;
			}
		    } // 1 - Marca embedded se valida(da usare per la firma a cui si riferisce)
		    if (tst != null) {
			s.setReferenceDate(tst.getTimeStampInfo().getGenTime());
			s.setReferenceDateType(TipoRifTemporale.MT_VERS_NORMA.toString());
		    } // 2 - Riferimento temporale settato da un TSD, TSR o M7M che si trova in una
		      // busta esterna a
		      // quella corrente
		    else if (input.getUseExternalTsdTsrM7MEnvelop().booleanValue()) {
			s.setReferenceDate(input.getReferenceDate());
			s.setReferenceDateType(TipoRifTemporale.MT_VERS_NORMA.toString());
		    } // 3 - La Marca detached (o embedded M7M) più vecchia tra le detached e solo
		      // se valida (da usare
		      // quindi per tutte le firme presenti)
		    else if (input.getDocumentAndTimeStampInfo() != null) {
			s.setReferenceDate(input.getDocumentAndTimeStampInfo().getTimeStampToken()
				.getTimeStampInfo().getGenTime());
			s.setReferenceDateType(TipoRifTemporale.MT_VERS_NORMA.toString());
		    } // 4 - Data riferimento temporale versato
		    else if (input.getReferenceDateType() != null && input.getReferenceDateType()
			    .equals(TipoRifTemporale.RIF_TEMP_VERS.toString())) {
			s.setReferenceDate(input.getReferenceDate());
			s.setReferenceDateType(input.getReferenceDateType());
		    } // 5 - Data di firma (da usare per la firma a cui si riferisce)
		    else if (s.getDateSignature() != null
			    && input.getUseSigninTimeAsReferenceDate()) {
			s.setReferenceDate(s.getDateSignature());
			s.setReferenceDateType(TipoRifTemporale.DATA_FIRMA.toString());
		    } // 6 - Data passata da chi chiama il metodo (variabile referenceDate, al
		      // versamento è pari alla
		      // data di versamento)
		    else {
			s.setReferenceDate(input.getReferenceDate());
			s.setReferenceDateType(TipoRifTemporale.DATA_VERS.toString());
		    }

		}
		if (performCounterSignaturesCheck) {
		    List<ISignature> counterSignatures = s.getCounterSignatures();
		    setReferenceDate(counterSignatures, input);
		}

	    }
	}

    }
}
