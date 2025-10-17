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

package it.eng.crypto.controller.impl.timestamp;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.eng.crypto.FactorySigner;
import it.eng.crypto.controller.bean.DocumentAndTimeStampInfoBean;
import it.eng.crypto.controller.bean.InputTimeStampBean;
import it.eng.crypto.controller.bean.OutputTimeStampBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.exception.CryptoStorageException;
import it.eng.crypto.storage.ICAStorage;
import it.eng.crypto.utils.VerificheEnums.EsitoControllo;
import it.eng.crypto.utils.VerificheEnums.TipoControlli;

public class TSAReliability extends AbstractTimeStampController {

    /**
     * Proprietà restituita dal metodo
     * {@link it.eng.crypto.controller.impl.signature.CertificateReliability#getCheckProperty
     * getCheckProperty}
     */
    public static final String TSA_RELIABILITY_CHECK = "performTSAReliability";
    Logger log = LoggerFactory.getLogger(TSAReliability.class.getName());

    public String getCheckProperty() {
	return TSA_RELIABILITY_CHECK;
    }

    @Override
    public boolean execute(InputTimeStampBean input, OutputTimeStampBean output)
	    throws ExceptionController {

	List<DocumentAndTimeStampInfoBean> documentAndTimeStampInfos = output
		.getDocumentAndTimeStampInfos();
	if (documentAndTimeStampInfos == null || documentAndTimeStampInfos.size() == 0) {
	    return false;
	}

	boolean result = true;

	for (DocumentAndTimeStampInfoBean documentAndTimeStampInfo : documentAndTimeStampInfos) {

	    TimeStampToken timeStampToken = documentAndTimeStampInfo.getTimeStampToken();
	    ValidationInfos validationInfos = documentAndTimeStampInfo.getValidationInfos();
	    ValidationInfos catenaValidationInfos = new ValidationInfos();
	    ValidationInfos certificatoValidationInfos = new ValidationInfos();
	    HashMap<String, Object> validityInfo = documentAndTimeStampInfo.getValidityInfo();
	    Date timestampDate = (Date) validityInfo.get(DocumentAndTimeStampInfoBean.PROP_DATE);
	    // Seriale identificativo della TSA
	    BigInteger tsaSerial = timeStampToken.getSID().getSerialNumber();
	    Boolean isCertificateInList = false;
	    Collection<CRL> embeddedCRLs = null;
	    Collection<Certificate> saCertificates = null;

	    try {

		// Refactored: Use Store and JcaX509CertificateConverter for certificates
		Store certStore = timeStampToken.getCertificates();
		Collection<org.bouncycastle.cert.X509CertificateHolder> certHolders = certStore
			.getMatches(null);
		saCertificates = new java.util.ArrayList<>();
		org.bouncycastle.cert.jcajce.JcaX509CertificateConverter certConverter = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
			.setProvider("BC");
		for (org.bouncycastle.cert.X509CertificateHolder holder : certHolders) {
		    saCertificates.add(certConverter.getCertificate(holder));
		}

		// Refactored: Use Store and convert X509CRLHolder to CRL
		Store crlStore = timeStampToken.getCRLs();
		Collection<org.bouncycastle.cert.X509CRLHolder> crlHolders = crlStore
			.getMatches(null);
		embeddedCRLs = new java.util.ArrayList<>();
		for (org.bouncycastle.cert.X509CRLHolder crlHolder : crlHolders) {
		    java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
			    .getInstance("X.509");
		    java.io.InputStream in = new java.io.ByteArrayInputStream(
			    crlHolder.getEncoded());
		    embeddedCRLs.add((CRL) cf.generateCRL(in));
		    in.close();
		}
		// Refactored: end
		// Controllo se il certificato di firma è attendibile
		ICAStorage certificatesAuthorityStorage = FactorySigner.getInstanceCAStorage();

		for (Certificate saCertificate : saCertificates) {
		    if (saCertificate instanceof X509Certificate) {

			X509Certificate saX509Certificate = (X509Certificate) saCertificate;
			// Controllo se il certificato corrisponde a quello della TSA
			if (saX509Certificate.getSerialNumber().equals(tsaSerial)) {

			    // # various interpretations of the RDN fields exist
			    // # the following are presented as generally accepted
			    // # values. In the case of personal certificates bizarre values
			    // # can appear in the fields
			    // # C = ISO3166 two character country code
			    // # ST = state or province
			    // # L = Locality; generally means city
			    // # O = Organization - Company Name
			    // # OU = Organization Unit - division or unit
			    // # CN = CommonName - entity name e.g. www.example.com
			    documentAndTimeStampInfo.setProperty(
				    DocumentAndTimeStampInfoBean.PROP_SID,
				    saX509Certificate.getSubjectX500Principal().getName());

			    // FIXED, UTILIZZAVA getDubjectDN invece dell geSubjectX500Principal
			    X509Certificate qualifiedCertificate = certificatesAuthorityStorage
				    .retriveCA(saX509Certificate.getSubjectX500Principal(),
					    signerUtil.getSubjectKeyId(saX509Certificate));

			    if (qualifiedCertificate == null) {

				// Se il soggetto non è accreditato, prova con l'issuer
				X509Certificate issuerCertificate = certificatesAuthorityStorage
					.retriveCA(saX509Certificate.getIssuerX500Principal(),
						signerUtil.getAuthorityKeyId(saX509Certificate));

				if (input.isCheckCAOnline()) {
				    // Potrebbe succedere che il DB delle CA (TSA) non sia ancora
				    // stato riempito. Provo
				    // a
				    // controllare ONLINE.
				    if (issuerCertificate == null) {
					X509Certificate tsaCert = signerUtil.getCACertificateOnline(
						saX509Certificate, certificatesAuthorityStorage);
					if (tsaCert != null) {
					    issuerCertificate = tsaCert;
					    try {
						// per motivi di performance aggiungo subito la CA
						// rischiando contesa
						// con i
						// job.
						certificatesAuthorityStorage.insertCA(tsaCert);
					    } catch (CryptoStorageException ex) {
						log.debug("Errore durante l'inserimento della CA ",
							ex);
					    }
					}
				    }
				}

				if (issuerCertificate == null) {
				    isCertificateInList = false;
				    // MODIFICATO PER IL PARER!! LA MARCA è VALIDA (o meglio può
				    // essere usata come
				    // riferimento
				    // temporale) ANCHE SE LA TSA NON è ACCREDITATA
				    validationInfos.addWarning(
					    "Il certificato della TSA non è accreditato");
				    catenaValidationInfos
					    .addError("Il certificato della TSA non è accreditato");
				    catenaValidationInfos.setEsito(EsitoControllo.NEGATIVO);
				} // Si considera qualificato il certificato se emesso da un issuer
				  // accreditato
				else {
				    try {
					saX509Certificate.verify(issuerCertificate.getPublicKey());
					qualifiedCertificate = saX509Certificate;
				    } catch (Exception e) {
					// MODIFICATO PER IL PARER!! LA MARCA è VALIDA ANCHE SE LA
					// TSA NON è
					// ACCREDITATA
					validationInfos.addWarning(
						"L'issuer della TSA è accreditato, ma il percorso di certificazione non è valido");
					catenaValidationInfos.addError(
						"L'issuer della TSA è accreditato, ma il percorso di certificazione non è valido");
					catenaValidationInfos.setEsito(EsitoControllo.NEGATIVO);
				    }
				}

			    }

			    if (qualifiedCertificate != null) {
				PublicKey publicKey = qualifiedCertificate.getPublicKey();
				if (org.bouncycastle.util.Arrays.constantTimeAreEqual(
					saCertificate.getPublicKey().getEncoded(),
					publicKey.getEncoded())) {
				    /*
				     * Verifico la data di scadenza temporale del certificato
				     * indicato nello storage
				     */
				    if (timestampDate.after(qualifiedCertificate.getNotAfter())) {
					validationInfos.addError(
						"La data di generazione della marca temporale: "
							+ timestampDate
							+ " è successiva alla data di scadenza del certificato: "
							+ qualifiedCertificate.getNotAfter());
					certificatoValidationInfos.addError(
						"La data di generazione della marca temporale: "
							+ timestampDate
							+ " è successiva alla data di scadenza del certificato: "
							+ qualifiedCertificate.getNotAfter());
					certificatoValidationInfos
						.setEsito(EsitoControllo.NEGATIVO);
					isCertificateInList = false;
					result = false;
				    } else if (timestampDate
					    .before(qualifiedCertificate.getNotBefore())) {
					validationInfos.addError(
						"La data di generazione della marca temporale: "
							+ timestampDate
							+ " è precedente alla data di inizio validità del certificato: "
							+ qualifiedCertificate.getNotBefore());
					certificatoValidationInfos.addError(
						"La data di generazione della marca temporale: "
							+ timestampDate
							+ " è precedente alla data di inizio validità del certificato: "
							+ qualifiedCertificate.getNotBefore());
					certificatoValidationInfos
						.setEsito(EsitoControllo.NEGATIVO);
					isCertificateInList = false;
					result = false;
				    } else {
					isCertificateInList = true;
					documentAndTimeStampInfo.setProperty(
						DocumentAndTimeStampInfoBean.PROP_QUALIFIED_CERTIFICATE,
						qualifiedCertificate);
				    }
				} else {
				    validationInfos.addError(
					    "La TSA indicata nel timestamp non corrisponde a quella salvata nello storage");
				    catenaValidationInfos.addError(
					    "La TSA indicata nel timestamp non corrisponde a quella salvata nello storage");
				    catenaValidationInfos.setEsito(EsitoControllo.NEGATIVO);
				    isCertificateInList = false;
				    result = false;
				}

			    }

			    documentAndTimeStampInfo.setProperty(
				    DocumentAndTimeStampInfoBean.PROP_CERTIFICATE,
				    qualifiedCertificate == null ? saCertificate
					    : qualifiedCertificate);

			}

		    }
		}
	    } catch (Exception e) {
		e.printStackTrace();
		return false;
	    }
	    documentAndTimeStampInfo.setProperty(TipoControlli.CATENA_TRUSTED.name(),
		    catenaValidationInfos);
	    documentAndTimeStampInfo.setProperty(TipoControlli.CERTIFICATO.name(),
		    certificatoValidationInfos);
	    documentAndTimeStampInfo.setProperty(
		    DocumentAndTimeStampInfoBean.PROP_RECOGNIZED_CERTIFICATE,
		    isCertificateInList.toString());
	}

	return result;
    }

}
