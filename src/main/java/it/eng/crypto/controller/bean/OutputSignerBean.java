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

package it.eng.crypto.controller.bean;

/**
 * Bean contenente tutte le proprietà di output settate dai vari controller durante il processo
 * principale. Attraverso gli step di analisi dei controller questo bean viene via via popolato
 * delle proprietà che ciascun controller estrae. Alla fine conterrà il risultato di un intero ciclo
 * di analisi. L'attributo 'child' contiene il riferimento ad un oggetto della medesima classe e
 * puo' essere valorizzato con il risultato del ciclo successivo. Sono definite le proprietà
 * indicate dai parametri seguenti:
 * <ul>
 * <li>ENVELOPE_FORMAT_PROPERTY: formato della busta</li>
 * <li>SIGNATURE_PROPERTY: lista delle firme</li>
 * <li>SIGNATURE_VALIDATION_PROPERTY: informazioni sulla validità di ciascuna firma</li>
 * <li>CERTIFICATE_EXPIRATION_PROPERTY: informazioni sulla scadenza dei certificati di ciascuna
 * firma</li>
 * <li>CRL_VALIDATION_PROPERTY: informazioni sulla revoca dei certificati</li>
 * <li>CERTIFICATE_UNQUALIFIED_PROPERTY: lista delle firme con certificato non riconosciuto</li>
 * <li>FORMAT_VALIDITY_PROPERTY: informazioni sulla validità del formato rispetto al periodo di
 * validità associato</li>
 * <li>TIME_STAMP_INFO_PROPERTY: informazioni sulle marche temporali associate</li>
 * </ul>
 *
 * @author Stefano Zennaro
 *
 */
public class OutputSignerBean extends OutputBean {

    /**
     * Tipo: String - formato della busta
     */
    public static final String ENVELOPE_FORMAT_PROPERTY = "Envelope Format";

    /**
     * Tipo: String - formato della busta
     */
    public static final String FORMAT_COMPLIANCE_PROPERTY = "Format Compliance Infos ";

    /**
     * Tipo: List<ISignature> - lista delle firme
     */
    public static final String SIGNATURE_PROPERTY = "Signatures";

    /**
     * Tipo: Map<ISignature, ValidationInfos> - informazioni sulla validità di ciascuna firma
     */
    public static final String SIGNATURE_VALIDATION_PROPERTY = "Signature Validation Infos";

    /**
     * Tipo: Map<ISignature, ValidationInfos> - informazioni sulla validità di ciascuna firma
     */
    public static final String CERTIFICATE_VALIDATION_PROPERTY = "Certficate Validation Infos";

    /**
     * Tipo: Map<ISignature, ValidationInfos> - informazioni sulla scadenza dei certificati di
     * ciascuna firma
     */
    public static final String CERTIFICATE_EXPIRATION_PROPERTY = "Certificate Expiration Infos";

    /**
     * Tipo: Map<ISignature, ValidationInfos> - informazioni sulla revoca dei certificati
     */
    public static final String CRL_VALIDATION_PROPERTY = "CRL Validation Infos";

    /**
     * Tipo: Map<ISignature, X509CRL> - memorizza la CRL utilizzata per il controllo di revoca
     */
    public static final String CRL_PROPERTY = "CRL Infos";

    /**
     * Tipo:List<ISignature> - lista delle firme con certificato non riconosciuto
     */
    public static final String CERTIFICATE_UNQUALIFIED_PROPERTY = "Unqualified certificates";

    /**
     * Tipo: ValidationInfos - informazioni sulla validità del formato rispetto al periodo di
     * validità associato
     */
    public static final String FORMAT_VALIDITY_PROPERTY = "Format validity";

    /**
     * Tipo: List<DocumentAndTimeStampInfo>
     */
    public static final String TIME_STAMP_INFO_PROPERTY = "TimeStampProperty";

    /**
     * Tipo: Map<ISignature, List<TrustChainCheck>> - corrispondenza tra firma e certificato di
     * certificazione accreditato-crl usata per il controllo di revoca del certificato
     */
    public static final String CERTIFICATE_RELIABILITY_PROPERTY = "CertificateReliabilityProperty";

    /**
     * Tipo: String - cone dell'eventuale controller che è andato in errore
     */
    public static final String MASTER_SIGNER_EXCEPTION_PROPERTY = "MasterSignerExceptionProperty";

    /*
     * Contenuto sbustato della firma
     */
    private ContentBean content;

    /**
     * Recupera il contenuto sbustato
     *
     * @return
     */
    public ContentBean getContent() {
	return content;
    }

    /**
     * Definisce il contenuto sbustato
     *
     * @param content
     */
    public void setContent(ContentBean content) {
	this.content = content;
    }

}
