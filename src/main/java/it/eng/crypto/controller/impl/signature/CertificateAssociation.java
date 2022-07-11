package it.eng.crypto.controller.impl.signature;

import it.eng.crypto.controller.bean.InputSignerBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.bean.TrustChainCheck;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.data.SignerUtil;
import it.eng.crypto.data.signature.ISignature;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Verifica la corretta corrispondenza tra il certificato dell'issuer e quello del firmatario
 *
 * @author Stefano Zennaro
 *
 */
public class CertificateAssociation extends AbstractSignerController {

    /**
     * Proprietà restituita dal metodo
     * {@link it.eng.crypto.controller.impl.signature.CertificateReliability#getCheckProperty getCheckProperty}
     */
    public static final String CERTIFICATE_ASSOCIATION_CHECK = "performCertificateAssociation";

    public String getCheckProperty() {
        return CERTIFICATE_ASSOCIATION_CHECK;
    }

    @Override
    public boolean execute(InputSignerBean input, OutputSignerBean output) throws ExceptionController {

        List<ISignature> signatures = null;
        Map<ISignature, ValidationInfos> validationInfosMap = new HashMap<ISignature, ValidationInfos>();
        Map<ISignature, List<TrustChainCheck>> certificateReliabilityMap = null;

        boolean result = true;

        if (output.getProperties().containsKey(OutputSignerBean.SIGNATURE_PROPERTY)) {
            signatures = (List<ISignature>) output.getProperty(OutputSignerBean.SIGNATURE_PROPERTY);
            certificateReliabilityMap = (Map<ISignature, List<TrustChainCheck>>) output
                    .getProperty(OutputSignerBean.CERTIFICATE_RELIABILITY_PROPERTY);
            result = populateValidationInfosMapFromSignatureList(validationInfosMap, signatures, input,
                    certificateReliabilityMap);
            output.setProperty(OutputSignerBean.CERTIFICATE_VALIDATION_PROPERTY, validationInfosMap);
        }
        return result;
    }

    private boolean populateValidationInfosMapFromSignatureList(Map<ISignature, ValidationInfos> validationInfosMap,
            List<ISignature> signatures, InputSignerBean input,
            Map<ISignature, List<TrustChainCheck>> certificateReliabilityMap) {
        boolean result = true;
        for (ISignature signature : signatures) {

            // Certificato del firmatario
            X509Certificate signatureCertificate = signature.getSignerBean().getCertificate();

            X509Certificate issuerCertificate = null;

            // Recupero il certificato accreditato (se presente)
            if (certificateReliabilityMap != null && certificateReliabilityMap.get(signature) != null) {
                issuerCertificate = certificateReliabilityMap.get(signature).get(0).getCerificate();
            }

            // se il certificato non è accreditato
            if (issuerCertificate == null) {
                Collection<? extends Certificate> embeddedCertificates = input.getSigner().getEmbeddedCertificates();
                if (embeddedCertificates != null) {
                    issuerCertificate = SignerUtil.getCertificateFromCollection(
                            signatureCertificate.getIssuerX500Principal(), embeddedCertificates);
                }
            }

            ValidationInfos validationInfos = new ValidationInfos();

            // Se non è stato possibile reperire il certificato dell'issuer
            // restituisco un errore
            if (issuerCertificate == null) {
                validationInfos.addWarning("Impossibile recuperare il certificato di certificazione");
                result = false;
            } else {
                try {
                    signatureCertificate.verify(issuerCertificate.getPublicKey());
                } catch (Exception e) {
                    validationInfos
                            .addError("Corrispondenza tra certificato dell'issuer e quello di firma non verificata");
                    result = false;
                }
            }
            validationInfosMap.put(signature, validationInfos);

            if (performCounterSignaturesCheck) {
                List<ISignature> counterSignatures = signature.getCounterSignatures();
                result = populateValidationInfosMapFromSignatureList(validationInfosMap, counterSignatures, input,
                        certificateReliabilityMap);
            }
        }
        return result;
    }
}
