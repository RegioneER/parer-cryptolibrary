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

package it.eng.crypto.utils;

import it.eng.crypto.controller.bean.DocumentAndTimeStampInfoBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.data.signature.ISignature;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class OutputAnalyzer {

    OutputSignerBean outputSignerBean;

    public OutputAnalyzer(OutputSignerBean outputSignerBean) {
        this.outputSignerBean = outputSignerBean;
    }

    /**
     * Stampa un report dettagliato della struttura che contiene l'esito delle analisi di file
     * firmati e marcati
     */
    public void printReport() {
        OutputSignerBean currentOutput = outputSignerBean;
        int step = 1;
        while (currentOutput != null) {
            System.out.println("************************************************************");
            System.out.println(" [ BUSTA " + step + "]");
            analyzeOutputStep(currentOutput);
            currentOutput = currentOutput.getChild();
            step++;
        }
    }

    /**
     * Recupera il numero di buste
     *
     * @return il numero di buste
     */
    public int getNumberOfEnvelopes() {
        OutputSignerBean currentOutput = outputSignerBean;
        int envelopes = 0;
        while (currentOutput != null) {
            currentOutput = currentOutput.getChild();
            envelopes++;
        }
        return envelopes;
    }

    /**
     * Recupera il numero di firme digitali
     *
     * @return il numero di firme digitali
     */
    public int getNumberOfSignatures() {
        OutputSignerBean currentOutput = outputSignerBean;
        int nSignatures = 0;
        while (currentOutput != null) {
            List<ISignature> signatures = (List<ISignature>) currentOutput
                    .getProperty(OutputSignerBean.SIGNATURE_PROPERTY);
            if (signatures != null) {
                nSignatures += signatures.size();
            }
            currentOutput = currentOutput.getChild();
        }
        return nSignatures;
    }

    /**
     * Recupera il numero di controfirme
     *
     * @return il numero di controfirme
     */
    public int getNumberOfCounterSignatures() {
        OutputSignerBean currentOutput = outputSignerBean;
        int nCounterSignatures = 0;
        while (currentOutput != null) {
            List<ISignature> signatures = (List<ISignature>) currentOutput
                    .getProperty(OutputSignerBean.SIGNATURE_PROPERTY);
            if (signatures != null) {
                for (ISignature signature : signatures) {
                    List<ISignature> counterSignatures = signature.getCounterSignatures();
                    if (counterSignatures != null) {
                        nCounterSignatures += counterSignatures.size();
                    }
                }
            }
            currentOutput = currentOutput.getChild();
        }
        return nCounterSignatures;
    }

    /**
     * Recupera il numero di firme marcate
     *
     * @return il numero di firme marcate
     */
    public int getNumberOfTimeStampedSignatures() {
        OutputSignerBean currentOutput = outputSignerBean;
        int nTimeStampedSignatures = 0;
        while (currentOutput != null) {
            List<DocumentAndTimeStampInfoBean> documentAndTimeStampInfos = (List<DocumentAndTimeStampInfoBean>) currentOutput
                    .getProperty(OutputSignerBean.TIME_STAMP_INFO_PROPERTY);
            if (documentAndTimeStampInfos != null) {
                List<ISignature> signatures = (List<ISignature>) currentOutput
                        .getProperty(OutputSignerBean.SIGNATURE_PROPERTY);
                if (signatures != null) {
                    nTimeStampedSignatures += signatures.size();
                }
            }
            currentOutput = currentOutput.getChild();
        }
        return nTimeStampedSignatures;
    }

    /**
     * Recupera i dati di accreditamento dei certificati di firma
     *
     * @return
     */
    public ValidationInfos getQualifiedCertificateInfos() {
        OutputSignerBean currentOutput = outputSignerBean;
        ValidationInfos result = new ValidationInfos();
        while (currentOutput != null) {
            Map<ISignature, ValidationInfos> unqualifiedSignatures = (Map<ISignature, ValidationInfos>) currentOutput
                    .getProperty(OutputSignerBean.CERTIFICATE_UNQUALIFIED_PROPERTY);
            if (unqualifiedSignatures != null) {
                Set<ISignature> unqualifiedSignatureSet = unqualifiedSignatures.keySet();
                for (ISignature unqualifiedSignature : unqualifiedSignatureSet) {
                    String subject = unqualifiedSignature.getSignerBean().getSubject().getName();
                    ValidationInfos unqualifiedInfos = unqualifiedSignatures
                            .get(unqualifiedSignature);
                    if (!unqualifiedInfos.isValid()) {
                        result.addError(subject + " ha una certificato di firma non accreditato: "
                                + unqualifiedInfos.getErrorsString());
                    }
                }

            }
            currentOutput = currentOutput.getChild();
        }
        return result;
    }

    /**
     * Recupera i dati di validità dei certificati (scadenza + corretta associazione)
     *
     * @return
     */
    public ValidationInfos getCertificateValidityInfos() {
        OutputSignerBean currentOutput = outputSignerBean;
        ValidationInfos result = new ValidationInfos();
        while (currentOutput != null) {
            Map<ISignature, ValidationInfos> certificateExpirations = (Map<ISignature, ValidationInfos>) currentOutput
                    .getProperty(OutputSignerBean.CERTIFICATE_EXPIRATION_PROPERTY);
            Map<ISignature, ValidationInfos> certificateAssociation = (Map<ISignature, ValidationInfos>) currentOutput
                    .getProperty(OutputSignerBean.CERTIFICATE_VALIDATION_PROPERTY);
            if (certificateExpirations != null) {
                Set<ISignature> expiredSignatureSet = certificateExpirations.keySet();
                for (ISignature expiredSignature : expiredSignatureSet) {
                    String subject = expiredSignature.getSignerBean().getSubject().getName();
                    ValidationInfos expirationInfos = certificateExpirations.get(expiredSignature);
                    if (!expirationInfos.isValid()) {
                        result.addError(subject + ": " + expirationInfos.getErrorsString());
                        if (expirationInfos.getWarnings() != null) {
                            result.addWarning(subject + ": " + expirationInfos.getWarningsString());
                        }
                    }
                }
            }
            if (certificateAssociation != null) {
                Set<ISignature> associatedSignatureSet = certificateExpirations.keySet();
                for (ISignature associatedSignature : associatedSignatureSet) {
                    String subject = associatedSignature.getSignerBean().getSubject().getName();
                    ValidationInfos associationInfos = certificateExpirations
                            .get(associatedSignature);
                    if (!associationInfos.isValid()) {
                        result.addError(subject + ": " + associationInfos.getErrorsString());
                        if (associationInfos.getWarnings() != null) {
                            result.addWarning(
                                    subject + ": " + associationInfos.getWarningsString());
                        }
                    }
                }
            }
            currentOutput = currentOutput.getChild();
        }
        return result;
    }

    /**
     * Recupera le informazioni sulle CRL
     *
     * @return
     */
    public ValidationInfos getCRLInfos() {
        OutputSignerBean currentOutput = outputSignerBean;
        ValidationInfos result = new ValidationInfos();
        while (currentOutput != null) {
            Map<ISignature, ValidationInfos> crlValidation = (Map<ISignature, ValidationInfos>) currentOutput
                    .getProperty(OutputSignerBean.CRL_VALIDATION_PROPERTY);
            if (crlValidation != null) {
                Set<ISignature> crlValidationSet = crlValidation.keySet();
                for (ISignature crlInfo : crlValidationSet) {
                    String subject = crlInfo.getSignerBean().getSubject().getName();
                    ValidationInfos crlValidationInfos = crlValidation.get(crlInfo);
                    if (!crlValidationInfos.isValid()) {
                        result.addError(subject + ": " + crlValidationInfos.getErrorsString());
                        if (crlValidationInfos.getWarnings() != null) {
                            result.addWarning(
                                    subject + ": " + crlValidationInfos.getWarningsString());
                        }
                    }
                }
            }
            currentOutput = currentOutput.getChild();
        }
        return result;
    }

    /**
     * Recupera le informazioni sulla validità delle firme
     *
     * @return
     */
    public ValidationInfos getSignatureValidationInfos() {
        OutputSignerBean currentOutput = outputSignerBean;
        ValidationInfos result = new ValidationInfos();
        while (currentOutput != null) {
            Map<ISignature, ValidationInfos> signatureValidations = (Map<ISignature, ValidationInfos>) currentOutput
                    .getProperty(OutputSignerBean.SIGNATURE_VALIDATION_PROPERTY);
            if (signatureValidations != null) {
                Set<ISignature> signatureValidationSet = signatureValidations.keySet();
                for (ISignature signatureValidation : signatureValidationSet) {
                    String subject = signatureValidation.getSignerBean().getSubject().getName();
                    ValidationInfos signatureValidationInfos = signatureValidations
                            .get(signatureValidation);
                    if (!signatureValidationInfos.isValid()) {
                        result.addError(
                                subject + ": " + signatureValidationInfos.getErrorsString());
                        if (signatureValidationInfos.getWarnings() != null) {
                            result.addWarning(
                                    subject + ": " + signatureValidationInfos.getWarningsString());
                        }
                    }
                }
            }
            currentOutput = currentOutput.getChild();
        }
        return result;
    }

    public ValidationInfos getValidationResults() {
        return getValidationResults(new OutputAnalyzerFilter());
    }

    public ValidationInfos getValidationResults(OutputAnalyzerFilter filter) {
        OutputSignerBean currentOutput = outputSignerBean;
        ValidationInfos validationResults = new ValidationInfos();
        while (currentOutput != null) {
            validateOutputStep(currentOutput, validationResults, filter);
            currentOutput = currentOutput.getChild();
        }
        return validationResults;
    }

    private void injectValidationInfos(ValidationInfos from, ValidationInfos to) {
        if (from == null) {
            return;
        }
        to.addErrors(from.getErrors());
        to.addWarnings(from.getWarnings());
    }

    protected void validateOutputStep(OutputSignerBean currentOutput,
            ValidationInfos validationInfos, OutputAnalyzerFilter filter) {

        /*
         * Proprietà in output
         */

        // TimeStamp
        List<DocumentAndTimeStampInfoBean> timeStampInfos = filter
                .isAcceptedOutput(OutputSignerBean.TIME_STAMP_INFO_PROPERTY)
                        ? (List<DocumentAndTimeStampInfoBean>) currentOutput
                                .getProperty(OutputSignerBean.TIME_STAMP_INFO_PROPERTY)
                        : null;

        // Formato busta
        String outputFormat = filter.isAcceptedOutput(OutputSignerBean.ENVELOPE_FORMAT_PROPERTY)
                ? (String) currentOutput.getProperty(OutputSignerBean.ENVELOPE_FORMAT_PROPERTY)
                : null;

        // Firme
        List<ISignature> signatures = filter.isAcceptedOutput(OutputSignerBean.SIGNATURE_PROPERTY)
                ? (List<ISignature>) currentOutput.getProperty(OutputSignerBean.SIGNATURE_PROPERTY)
                : null;

        // Validità delle firme
        Map<ISignature, ValidationInfos> signatureValidations = filter
                .isAcceptedOutput(OutputSignerBean.SIGNATURE_VALIDATION_PROPERTY)
                        ? (Map<ISignature, ValidationInfos>) currentOutput
                                .getProperty(OutputSignerBean.SIGNATURE_VALIDATION_PROPERTY)
                        : null;

        // Validità del formato
        Map<ISignature, ValidationInfos> formatValidity = filter
                .isAcceptedOutput(OutputSignerBean.FORMAT_VALIDITY_PROPERTY)
                        ? (Map<ISignature, ValidationInfos>) currentOutput
                                .getProperty(OutputSignerBean.FORMAT_VALIDITY_PROPERTY)
                        : null;

        // Scadenza dei certificati
        Map<ISignature, ValidationInfos> certificateExpirations = filter
                .isAcceptedOutput(OutputSignerBean.CERTIFICATE_EXPIRATION_PROPERTY)
                        ? (Map<ISignature, ValidationInfos>) currentOutput
                                .getProperty(OutputSignerBean.CERTIFICATE_EXPIRATION_PROPERTY)
                        : null;

        // Revoca dei certificati
        Map<ISignature, ValidationInfos> crlValidation = filter
                .isAcceptedOutput(OutputSignerBean.CRL_VALIDATION_PROPERTY)
                        ? (Map<ISignature, ValidationInfos>) currentOutput
                                .getProperty(OutputSignerBean.CRL_VALIDATION_PROPERTY)
                        : null;

        // Certificati accreditati
        Map<ISignature, ValidationInfos> unqualifiedSignatures = filter
                .isAcceptedOutput(OutputSignerBean.CERTIFICATE_UNQUALIFIED_PROPERTY)
                        ? (Map<ISignature, ValidationInfos>) currentOutput
                                .getProperty(OutputSignerBean.CERTIFICATE_UNQUALIFIED_PROPERTY)
                        : null;

        // Validità dei certificati
        Map<ISignature, ValidationInfos> certificateAssociation = filter
                .isAcceptedOutput(OutputSignerBean.CERTIFICATE_VALIDATION_PROPERTY)
                        ? (Map<ISignature, ValidationInfos>) currentOutput
                                .getProperty(OutputSignerBean.CERTIFICATE_VALIDATION_PROPERTY)
                        : null;

        // Errore durante l'esecuzione di un controllo bloccante
        String masterSignerException = filter
                .isAcceptedOutput(OutputSignerBean.MASTER_SIGNER_EXCEPTION_PROPERTY)
                        ? (String) currentOutput
                                .getProperty(OutputSignerBean.MASTER_SIGNER_EXCEPTION_PROPERTY)
                        : null;

        if (timeStampInfos != null && timeStampInfos.size() != 0) {
            for (DocumentAndTimeStampInfoBean timeStampInfo : timeStampInfos) {
                injectValidationInfos(timeStampInfo.getValidationInfos(), validationInfos);
            }
        }

        int i = 1;
        if (signatures != null) {
            if (masterSignerException != null && !"".equals(masterSignerException.trim())) {
                validationInfos.addError(
                        "Errore durante l'esecuzione dei controlli relativo al controller: "
                                + masterSignerException);
            }

            for (ISignature signature : signatures) {
                injectValidationInfos(formatValidity.get(signature), validationInfos);
                injectValidationInfos(signatureValidations.get(signature), validationInfos);

                if (certificateExpirations != null) {
                    injectValidationInfos(certificateExpirations.get(signature), validationInfos);
                }

                if (crlValidation != null) {
                    injectValidationInfos(crlValidation.get(signature), validationInfos);
                }

                if (certificateAssociation != null) {
                    injectValidationInfos(certificateAssociation.get(signature), validationInfos);
                }

                if (unqualifiedSignatures != null) {
                    ValidationInfos certificateReliabilityInfo = unqualifiedSignatures
                            .get(signature);
                    if (certificateReliabilityInfo != null) {
                        validationInfos.addError(
                                createCertificateReliabilityError(certificateReliabilityInfo));
                    }
                }

                List<ISignature> counterSignatures = signature.getCounterSignatures();
                if (counterSignatures != null && counterSignatures.size() != 0) {
                    String signatureIndex = "[" + i + "]";
                    validateCounterSignatures(validationInfos, signatureIndex, counterSignatures,
                            signatureValidations, certificateExpirations, crlValidation,
                            unqualifiedSignatures);
                }
                i++;
            }
        }
    }

    private void validateCounterSignatures(ValidationInfos validationInfos, String signatureIndex,
            List<ISignature> countersignatures,
            Map<ISignature, ValidationInfos> signatureValidations,
            Map<ISignature, ValidationInfos> certificateExpirations,
            Map<ISignature, ValidationInfos> crlValidation,
            Map<ISignature, ValidationInfos> unqualifiedSignatures) {
        int i = 1;
        for (ISignature countersignature : countersignatures) {
            validateCounterSignature(validationInfos, countersignature, signatureValidations,
                    certificateExpirations, crlValidation, unqualifiedSignatures);
            List<ISignature> counterCountersignatures = countersignature.getCounterSignatures();
            if (counterCountersignatures != null && counterCountersignatures.size() != 0) {
                validateCounterSignatures(validationInfos, signatureIndex + "[" + i + "]",
                        counterCountersignatures, signatureValidations, certificateExpirations,
                        crlValidation, unqualifiedSignatures);
            }
            i++;
        }
    }

    protected void validateCounterSignature(ValidationInfos validationInfos,
            ISignature countersignature, Map<ISignature, ValidationInfos> signatureValidations,
            Map<ISignature, ValidationInfos> certificateExpirations,
            Map<ISignature, ValidationInfos> crlValidation,
            Map<ISignature, ValidationInfos> unqualifiedSignatures) {

        injectValidationInfos(signatureValidations.get(countersignature), validationInfos);

        if (certificateExpirations != null) {
            injectValidationInfos(certificateExpirations.get(countersignature),
                    signatureValidations.get(countersignature));
        }

        if (crlValidation != null) {
            injectValidationInfos(crlValidation.get(countersignature), validationInfos);
        }

        if (unqualifiedSignatures != null) {
            ValidationInfos certificateReliabilityInfo = unqualifiedSignatures
                    .get(countersignature);
            if (certificateReliabilityInfo != null) {
                validationInfos
                        .addError(createCertificateReliabilityError(certificateReliabilityInfo));
            }
        }
    }

    private String createCertificateReliabilityError(ValidationInfos certificateReliabilityInfo) {
        String errorMessage = "Certificato della firma NON ACCREDITATO: ";
        String[] errors = certificateReliabilityInfo.getErrors();
        if (errors != null) {
            errorMessage += " errors:[";
            for (String error : certificateReliabilityInfo.getErrors()) {
                errorMessage += error + ", ";
            }
            errorMessage += "]";
        }
        String[] warnings = certificateReliabilityInfo.getWarnings();
        if (warnings != null) {
            errorMessage += " warnings:[";
            for (String warning : certificateReliabilityInfo.getWarnings()) {
                errorMessage += warning + ", ";
            }
            errorMessage += "]";
        }
        return errorMessage;
    }

    protected void analyzeOutputStep(OutputSignerBean currentOutput) {

        /*
         * Proprietà in output
         */
        List<DocumentAndTimeStampInfoBean> timeStampInfos = (List<DocumentAndTimeStampInfoBean>) currentOutput
                .getProperty(OutputSignerBean.TIME_STAMP_INFO_PROPERTY);
        String outputFormat = (String) currentOutput
                .getProperty(OutputSignerBean.ENVELOPE_FORMAT_PROPERTY);
        List<ISignature> signatures = (List<ISignature>) currentOutput
                .getProperty(OutputSignerBean.SIGNATURE_PROPERTY);
        Map<ISignature, ValidationInfos> signatureValidations = (Map<ISignature, ValidationInfos>) currentOutput
                .getProperty(OutputSignerBean.SIGNATURE_VALIDATION_PROPERTY);
        Map<ISignature, ValidationInfos> formatValidity = (Map<ISignature, ValidationInfos>) currentOutput
                .getProperty(OutputSignerBean.FORMAT_VALIDITY_PROPERTY);
        Map<ISignature, ValidationInfos> certificateExpirations = (Map<ISignature, ValidationInfos>) currentOutput
                .getProperty(OutputSignerBean.CERTIFICATE_EXPIRATION_PROPERTY);
        Map<ISignature, ValidationInfos> crlValidation = (Map<ISignature, ValidationInfos>) currentOutput
                .getProperty(OutputSignerBean.CRL_VALIDATION_PROPERTY);
        Map<ISignature, ValidationInfos> unqualifiedSignatures = (Map<ISignature, ValidationInfos>) currentOutput
                .getProperty(OutputSignerBean.CERTIFICATE_UNQUALIFIED_PROPERTY);
        Map<ISignature, ValidationInfos> certificateAssociation = (Map<ISignature, ValidationInfos>) currentOutput
                .getProperty(OutputSignerBean.CERTIFICATE_VALIDATION_PROPERTY);
        String masterSignerException = (String) currentOutput
                .getProperty(OutputSignerBean.MASTER_SIGNER_EXCEPTION_PROPERTY);

        if (timeStampInfos == null || timeStampInfos.size() == 0) {
            System.out.println("Timestamp non trovato");
        } else {
            for (DocumentAndTimeStampInfoBean timeStampInfo : timeStampInfos) {
                System.out.println("Marca temporale: \n" + timeStampInfo);
            }
        }

        int nFirme = signatures == null ? 0 : signatures.size();
        System.out.println("\nNumero di firme: " + nFirme + "\n");

        int i = 1;
        if (signatures != null) {
            System.out.println("Formato della busta: " + outputFormat);
            if (masterSignerException != null && !"".equals(masterSignerException.trim())) {
                System.out.println(
                        "Errore durante l'esecuzione dei controlli relativo al controller: "
                                + masterSignerException);
            } else {
                System.out.println("Esecuzione dei controlli conclusa correttamente");
            }
            System.out.println("Controllo di validità temporale del formato: " + formatValidity);
            for (ISignature signature : signatures) {

                System.out.println("\n[Firma " + i + "]");

                ValidationInfos signatureValidationInfos = signatureValidations.get(signature);
                System.out.println("\t Validazione della firma: " + signatureValidationInfos);

                if (certificateExpirations != null) {
                    ValidationInfos certificateExpirationInfos = certificateExpirations
                            .get(signature);
                    System.out
                            .println("\t Scadenza del certificato: " + certificateExpirationInfos);
                }

                if (crlValidation != null) {
                    ValidationInfos crlValidationInfos = crlValidation.get(signature);
                    System.out.println("\t Revoca del certificato: " + crlValidationInfos);
                }

                if (certificateAssociation != null) {
                    ValidationInfos certificateAssociationInfos = certificateAssociation
                            .get(signature);
                    System.out.println("\t Associazione tra certificato di firma e issuer: "
                            + certificateAssociationInfos);
                }

                if (unqualifiedSignatures != null) {
                    ValidationInfos certificateReliabilityInfo = unqualifiedSignatures
                            .get(signature);
                    if (certificateReliabilityInfo != null) {
                        System.out.println("\t Certificato di firma NON ACCREDITATO: "
                                + certificateReliabilityInfo);
                    } else {
                        System.out.println("\t Certificato di firma ACCREDITATO");
                    }
                }

                List<ISignature> counterSignatures = signature.getCounterSignatures();
                if (counterSignatures != null && counterSignatures.size() != 0) {
                    String padding = "\t\t";
                    String signatureIndex = "[" + i + "]";
                    printCounterSignatures(padding, signatureIndex, counterSignatures,
                            signatureValidations, certificateExpirations, crlValidation,
                            unqualifiedSignatures);
                }
                i++;
            }
        }
    }

    protected void printCounterSignatures(String padding, String signatureIndex,
            List<ISignature> countersignatures,
            Map<ISignature, ValidationInfos> signatureValidations,
            Map<ISignature, ValidationInfos> certificateExpirations,
            Map<ISignature, ValidationInfos> crlValidation,
            Map<ISignature, ValidationInfos> unqualifiedSignatures) {
        System.out.println("\t La firma " + signatureIndex + ". contiene "
                + countersignatures.size() + " controfirme");
        int i = 1;
        for (ISignature countersignature : countersignatures) {
            printCounterSignatureCheck(padding, countersignature, signatureValidations,
                    certificateExpirations, crlValidation, unqualifiedSignatures);
            List<ISignature> counterCountersignatures = countersignature.getCounterSignatures();
            if (counterCountersignatures != null && counterCountersignatures.size() != 0) {
                String newPadding = padding + "\t";
                printCounterSignatures(newPadding, signatureIndex + "[" + i + "]",
                        counterCountersignatures, signatureValidations, certificateExpirations,
                        crlValidation, unqualifiedSignatures);
            }
            i++;
        }
    }

    protected void printCounterSignatureCheck(String padding, ISignature countersignature,
            Map<ISignature, ValidationInfos> signatureValidations,
            Map<ISignature, ValidationInfos> certificateExpirations,
            Map<ISignature, ValidationInfos> crlValidation,
            Map<ISignature, ValidationInfos> unqualifiedSignatures) {
        ValidationInfos countersignatureValidationInfos = signatureValidations
                .get(countersignature);
        System.out.println(
                padding + " Validazione della controfirma: " + countersignatureValidationInfos);

        if (certificateExpirations != null) {
            ValidationInfos countersignatureCertificateExpirationInfos = certificateExpirations
                    .get(countersignature);
            System.out.println(padding + " Scadenza del certificato della controfirma: "
                    + countersignatureCertificateExpirationInfos);
        }

        if (crlValidation != null) {
            ValidationInfos countersignatureCrlValidationInfos = crlValidation
                    .get(countersignature);
            System.out.println(padding + " Revoca del certificato della controfirma: "
                    + countersignatureCrlValidationInfos);
        }

        if (unqualifiedSignatures != null) {
            ValidationInfos certificateReliabilityInfo = unqualifiedSignatures
                    .get(countersignature);
            if (certificateReliabilityInfo != null) {
                System.out.println(padding + " Certificato della controfirma NON ACCREDITATO: "
                        + certificateReliabilityInfo);
            } else {
                System.out.println(padding + " Certificato della controfirma ACCREDITATO");
            }
        }
    }
}
