package it.eng.crypto.data;

import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.data.signature.ISignature;
import it.eng.crypto.data.signature.XAdESSignature;
import it.eng.crypto.data.type.SignerType;
import it.eng.crypto.provider.MyDOMXMLSignatureFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.commons.io.FileUtils;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.mityc.firmaJava.libreria.xades.DatosFirma;
import es.mityc.firmaJava.libreria.xades.DatosNodosFirmados;
import es.mityc.firmaJava.libreria.xades.DatosSelloTiempo;
import es.mityc.firmaJava.libreria.xades.DatosTipoFirma;
import es.mityc.firmaJava.libreria.xades.EnumFormatoFirma;
import es.mityc.firmaJava.libreria.xades.ResultadoEnum;
import es.mityc.firmaJava.libreria.xades.ResultadoValidacion;
import es.mityc.firmaJava.libreria.xades.ValidarFirmaXML;
import es.mityc.firmaJava.libreria.xades.errores.FirmaXMLError;
import it.eng.crypto.data.util.ParserPool;
import it.eng.crypto.exception.XmlParserException;
import it.eng.crypto.manager.SignatureManager;
import java.nio.file.Files;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import org.apache.commons.io.IOUtils;
import org.apache.xml.security.Init;

/**
 * Implementa i controlli su firme di tipo XAdES. Il contenuto di un file è riconosciuto se implementa le specifiche
 * ETSI TS 101 903
 *
 * @author Stefano Zennaro
 *
 */
public class XMLSigner extends AbstractSigner {

    private ParserPool parserPool;

    static {
        Init.init();
    }
    private ValidarFirmaXML xmlValidator;
    /*
     * Lista degli elementi Signature contenuti all'interno del file XML
     */
    private List<XMLSignature> xmlSignatures = null;
    /*
     * Il nodo signature contenente il timestamp
     */
    private Node timeStampSignatureNode = null;
    private Node signatureValueNode = null;
    private SignerType type = null;
    // Si suppone che il metodo di canonicalizzazione del contenuto xml
    // sia lo stesso per tutte le firme
    private String canonicalizationMethod = null;
    private List<ResultadoValidacion> validationResults;
    // Il documento XML parserizzato
    private Document doc = null;

    public XMLSigner() {
        xmlValidator = new ValidarFirmaXML();
    }

    private void populateValidationResults(File file, DocumentBuilder db) throws FirmaXMLError {
        validationResults = null;
        timestamptokens = null;

        validationResults = xmlValidator.validar(file, null, db);
        ArrayList<TimeStampToken> timestamptokenList = new ArrayList<TimeStampToken>();
        for (ResultadoValidacion validationResult : validationResults) {
            DatosFirma signatureData = validationResult.getDatosFirma();
            List<DatosSelloTiempo> timeInfos = signatureData.getDatosSelloTiempo();
            if (timeInfos != null && timeInfos.size() != 0) {
                timestamptokenList.add(timeInfos.get(0).getTst());
            }
        }
        if (timestamptokenList.size() != 0) {
            timestamptokens = timestamptokenList.toArray(new TimeStampToken[timestamptokenList.size()]);
        }
    }

    public boolean isSignedType(byte[] content, ValidationInfos complianceCheck) {
        File tmpFile = null;
        FileOutputStream fos = null;
        try {
            tmpFile = File.createTempFile("tmp-xml-signer-", null);
            tmpFile.deleteOnExit(); // Inutile
            fos = new FileOutputStream(tmpFile);
            fos.write(content);
            return isSignedType(tmpFile, complianceCheck);
        } catch (IOException e) {
        } finally {
            try {
                if (fos != null) {
                    fos.close();
                }
                if (tmpFile != null) {
                    Files.deleteIfExists(tmpFile.toPath());
                }
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        return false;
    }

    /**
     * Restituisce true se il contenuto del file rispetta lo schema XAdES e contiene almeno una firma (nodo signature)
     * ed eventualmente un timestamp
     */
    public boolean isSignedType(File file, ValidationInfos complianceCheck) {
        // Resetto il signer
        reset();
        this.type = null;
        InputStream stream = null;
        DocumentBuilder db = null;
        try {
            stream = FileUtils.openInputStream(file);
            db = parserPool.getBuilder();
            doc = db.parse(stream);
            if (doc != null) {
                SignatureManager.setIsXml(true);
            }
            db.reset();
            populateValidationResults(file, db);
        } catch (Exception e) {
            if (xmlValidator != null && xmlValidator.getResultado() != null
                    && xmlValidator.getResultado().getLog() != null
                    && xmlValidator.getResultado().getLog().length() > 0) {
                complianceCheck.addWarning(xmlValidator.getResultado().getLog());
            }
            if (validationResults != null) {
                for (ResultadoValidacion res : validationResults) {
                    if (res.getResultado().equals(ResultadoEnum.INVALID)
                            || res.getResultado().equals(ResultadoEnum.UNKNOWN)) {
                        complianceCheck.addWarning(res.getLog());

                    }
                }
            }
            return false;
        } finally {
            if (db != null) {
                parserPool.returnBuilder(db);
            }
            if (stream != null) {
                IOUtils.closeQuietly(stream);
            }
        }

        if (validationResults == null) {
            return false;
        }

        // Nuovo controllo di conformità ...
        boolean invalid = false;
        boolean unknown = false;
        for (ResultadoValidacion res : validationResults) {
            // if(res.getDatosFirma()!=null &&
            // res.getDatosFirma().getTipoFirma().getTipoXAdES().equals(EnumFormatoFirma.XMLSignature)) continue;
            if (res.getResultado().equals(ResultadoEnum.INVALID)) {
                if (res.getDatosFirma().getContraFirma() != null && !res.getDatosFirma().getContraFirma().isEmpty()) {
                    complianceCheck.addWarning("Errore nella controfirma: " + res.getLog());
                } else {
                    complianceCheck.addWarning(res.getLog());
                }
                // FIX by LS
                if (res.getDatosFirma().getTipoFirma() == null) {
                    res.getDatosFirma().setTipoFirma(new DatosTipoFirma());
                }

                res.getDatosFirma().getTipoFirma().setTipoXAdES(EnumFormatoFirma.XMLSignature);

                invalid = true;
            } else if (res.getResultado().equals(ResultadoEnum.UNKNOWN)) {
                res.getDatosFirma().getTipoFirma().setTipoXAdES(EnumFormatoFirma.XMLSignature);
                unknown = true;
            }
        }

        // Se almeno una firma è sconosciuta o invalida secondo la libreria mityc potrebbe comunque essere una firma
        // XML-DSIG
        if (unknown || invalid) {
            return this.isXmlDigSig(complianceCheck);
        }

        /*
         * Attualmente si assume che tutte le firme (parallele) contenute all'interno dello stesso file abbiano lo
         * stesso formato
         */
        ResultadoValidacion result = validationResults.get(0);
        DatosTipoFirma tipoFirma = result.getDatosFirma().getTipoFirma();
        if (tipoFirma == null) {
            return false;
        }

        this.type = enumFormatoFirma2SignerType(tipoFirma.getTipoXAdES());

        /*
         * Parserizza il documento per ricavare gli elementi contenenti le firme
         */
        try {

            NodeList signatureNodesList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (signatureNodesList.getLength() == 0) {
                throw new Exception("Cannot find Signature element");
            }
            for (int i = 0; i < signatureNodesList.getLength(); i++) {

                Node signatureNode = signatureNodesList.item(i);

                XMLSignatureFactory factory = MyDOMXMLSignatureFactory.getInstance("DOM", "MyXMLDSig");
                DOMStructure struct = new DOMStructure(signatureNode);

                XMLSignature xmlSignature = factory.unmarshalXMLSignature(struct);

                /*
                 * In questo modo si ritiene che una sola firma contenga un timestamp TODO: - se più firme lo contengono
                 * occorrerebbe confrontarne il contenuto, per verificare che si tratta di firme orizzontali
                 */
                if (signatureNode instanceof Element) {
                    Element signatureNodeElement = (Element) signatureNode;
                    if (xmlSignatures == null) {
                        xmlSignatures = new ArrayList<XMLSignature>();
                    }
                    xmlSignatures.add(xmlSignature);

                    NodeList objectsList = signatureNodeElement.getElementsByTagNameNS(XMLSignature.XMLNS, "Object");
                    for (int j = 0; j < objectsList.getLength(); ++j) {
                        Node object = objectsList.item(j);
                        if (object instanceof Element) {

                            Element objectElement = (Element) object;
                            String objectNameSpace = null;

                            NamedNodeMap attributes = objectElement.getAttributes();

                            for (int k = 0; k < attributes.getLength(); ++k) {
                                Node attributeNode = attributes.item(k);
                                String attributeName = attributeNode.getNodeName();
                                if (attributeName.startsWith("xmlns") && attributeName.length() > 6) {
                                    objectNameSpace = attributeName.substring(6);
                                    break;
                                }
                            }
                            if (objectNameSpace == null && objectElement.getFirstChild() != null) {
                                attributes = objectElement.getFirstChild().getAttributes();
                                for (int k = 0; k < attributes.getLength(); ++k) {
                                    Node attributeNode = attributes.item(k);
                                    String attributeName = attributeNode.getNodeName();
                                    if (attributeName.startsWith("xmlns") && attributeName.length() > 6) {
                                        objectNameSpace = attributeName.substring(6);
                                        break;
                                    }
                                }
                            }

                            NodeList timeStampTokenList = objectNameSpace == null
                                    ? objectElement.getElementsByTagName("SignatureTimeStamp")
                                    : objectElement.getElementsByTagName(objectNameSpace + ":SignatureTimeStamp");
                            if (timeStampTokenList.getLength() == 1) {
                                timeStampSignatureNode = signatureNode;
                                Node timeStampTokenNode = timeStampTokenList.item(0);
                                if (timeStampTokenNode instanceof Element) {
                                    Element timeStampTokenElement = (Element) timeStampTokenNode;
                                    NodeList canonicalizationMethodList = timeStampTokenElement
                                            .getElementsByTagName("CanonicalizationMethod");
                                    if (canonicalizationMethodList == null
                                            || canonicalizationMethodList.getLength() == 0) {
                                        canonicalizationMethodList = timeStampTokenElement
                                                .getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
                                    }
                                    if (canonicalizationMethodList != null
                                            && canonicalizationMethodList.getLength() != 0) {
                                        Node canonicalizationMethodNode = canonicalizationMethodList.item(0);
                                        if (canonicalizationMethodNode instanceof Element) {
                                            canonicalizationMethod = ((Element) canonicalizationMethodNode)
                                                    .getAttribute("Algorithm");
                                        }
                                    }
                                }
                            }
                        }
                    }

                }
            }
        } catch (NoSuchProviderException e) {
            log.error("Provider XML per la verifica firme non trovato", e);
            throw new ProviderException("Provider XML per la verifica firme non trovato", e);
        } catch (Exception e) {
            // Nonostante sia stato generato un errore, può
            // comunque essere una firma di tipo XAdES in quanto
            // si può trattare di un errore di decodifica di una parte
            // nel caso il tipo di formato sia stato rilevato, restituisco
            // comunque true
            if (this.type != null) {
                return true;
            } else {
                return false;
            }

        }
        return this.type != null && xmlSignatures != null;
    }

    public TimeStampToken[] getTimeStampTokens() {
        if (timestamptokens == null && this.type == null) {
            DocumentBuilder db = null;
            try {
                db = parserPool.getBuilder();
                populateValidationResults(file, db);
            } catch (FirmaXMLError e) {
            } catch (XmlParserException e) {
                log.error("Errore nel recupero di un DocumentBuilder dal pool", e);
            } finally {
                if (db != null) {
                    parserPool.returnBuilder(db);
                }
            }
        }
        return timestamptokens;
    }

    /**
     * Metodo di utilità che consente di mappare il formato {@link es.mityc.firmaJava.libreria.xades.EnumFormatoFirma}
     * nel corrispondente tipo it.eng.crypto.data.type.SignerType
     *
     * @param formatoFirma
     *            formato firma in input
     * 
     * @return formato corrispondente
     */
    public static final SignerType enumFormatoFirma2SignerType(EnumFormatoFirma formatoFirma) {
        switch (formatoFirma) {
        case XAdES_BES:
            return SignerType.XADES_BES;
        case XAdES_C:
            return SignerType.XADES_C;
        case XAdES_T:
            return SignerType.XADES_T;
        case XAdES_X:
            return SignerType.XADES_X;
        case XAdES_XL:
            return SignerType.XADES_XL;
        case XMLSignature:
            return SignerType.XML_DSIG;
        default:
            return SignerType.XADES;
        }
    }

    private Node parseSignatureForSignatureValue(Node signatureNode) {
        Node signatureValueNode = null;
        if (signatureNode instanceof Element) {
            Element signatureNodeElement = (Element) signatureNode;
            NodeList signatureValueList = signatureNodeElement.getElementsByTagNameNS(XMLSignature.XMLNS,
                    "SignatureValue");
            if (signatureValueList != null && signatureValueList.getLength() != 0) {
                signatureValueNode = signatureValueList.item(0);
            }
        }
        return signatureValueNode;
    }

    public ValidationInfos validateTimeStampTokensEmbedded() {
        ValidationInfos validationInfos = new ValidationInfos();

        if (xmlSignatures == null || xmlSignatures.size() == 0) {
            validationInfos.addError("Il file in ingresso non contiene alcuna firma");
            return validationInfos;
        }
        if (this.timestamptokens == null || timestamptokens.length == 0) {
            if (!this.isSignedType(file, validationInfos)) {
                validationInfos.addError("File non in formato: " + this.getFormat());
                return validationInfos;
            } else {
                getTimeStampTokens();
            }
        }

        // validationInfos.setValidatedObject(timestamptoken);
        if (type == SignerType.XADES || type == SignerType.XADES_BES) {
            validationInfos.addError("Il formato: " + this.type + " non contiene una marca temporale");
            return validationInfos;
        }

        for (TimeStampToken timestamptoken : timestamptokens) {
            TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
            String hashAlgOID = timestamptoken.getTimeStampInfo().getMessageImprintAlgOID();
            MessageDigest digest;
            String canonicalizerID = null;
            try {

                digest = MessageDigest.getInstance(hashAlgOID);
                byte[] buffer = null;
                if (signatureValueNode == null) {
                    signatureValueNode = parseSignatureForSignatureValue(timeStampSignatureNode);
                }

                /*
                 * Formatto in maniera canonica il contenuto del nodo signature
                 */
                canonicalizerID = (canonicalizationMethod == null || "".equals(canonicalizationMethod.trim()))
                        ? org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS
                        : canonicalizationMethod;
                org.apache.xml.security.c14n.Canonicalizer canonicalizer = org.apache.xml.security.c14n.Canonicalizer
                        .getInstance(canonicalizerID);
                // canonicalizerID = (canonicalizationMethod == null || "".equals(canonicalizationMethod.trim()) ) ?
                // com.sun.org.apache.xml.internal.security.c14n.Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS :
                // canonicalizationMethod;
                // org.apache.xml.security.c14n.Canonicalizer canonicalizer =
                // org.apache.xml.security.c14n.Canonicalizer.getInstance(canonicalizerID);

                buffer = canonicalizer.canonicalizeSubtree(signatureValueNode);

                TimeStampRequest request = gen.generate(hashAlgOID, digest.digest(buffer));
                checkTimeStampTokenOverRequest(validationInfos, timestamptoken, request);
            } catch (NoSuchAlgorithmException e) {
                validationInfos.addError(
                        "Impossibile validare la marca poichè l'algoritmo di calcolo non è supportato: " + hashAlgOID);
            } catch (Exception e) {
                validationInfos.addError(
                        "Impossibile validare la marca poichè l'algoritmo di canonicalizzazione non è supportato: "
                                + canonicalizerID);
            }
        }
        return validationInfos;
    }

    public ValidationInfos validateTimeStampTokensEmbedded(TimeStampToken timeStampToken) {
        ValidationInfos validationInfos = new ValidationInfos();

        if (xmlSignatures == null || xmlSignatures.size() == 0) {
            validationInfos.addError("Il file in ingresso non contiene alcuna firma");
            return validationInfos;
        }
        if (this.timestamptokens == null || timestamptokens.length == 0) {
            if (!this.isSignedType(file, validationInfos)) {
                validationInfos.addError("File non in formato: " + this.getFormat());
                return validationInfos;
            } else {
                getTimeStampTokens();
            }
        }

        for (ResultadoValidacion validationResult : validationResults) {
            DatosFirma signatureData = validationResult.getDatosFirma();
            List<DatosSelloTiempo> timeInfos = signatureData.getDatosSelloTiempo();
            if (timeInfos != null && timeInfos.size() != 0) {
                timeStampToken.equals(timeInfos.get(0).getTst());
                return validationInfos;

            }
        }
        return validationInfos;
    }

    public SignerType getFormat() {
        return this.type;
    }

    public InputStream getUnsignedContent() {
        /*
         * Si ritiene che tutte le firme parallele si rieferiscano allo stesso contenuto
         */
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ResultadoValidacion result = validationResults.get(0);
        List<DatosNodosFirmados> signedNodes = result.getDatosFirma().getDatosNodosFirmados();
        try {
            for (DatosNodosFirmados signedData : signedNodes) {
                if (signedData.getNodoFirmadoBytes() != null) {
                    bos.write(signedData.getNodoFirmadoBytes());
                }
            }
            bos.flush();
        } catch (IOException e) {
            log.error("Errore IO", e);
            return null;
        }
        return new ByteArrayInputStream(bos.toByteArray());
    }

    public byte[] getUnsignedContentDigest(MessageDigest digestAlgorithm) {
        /*
         * Si ritiene che tutte le firme parallele si rieferiscano allo stesso contenuto
         */
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ResultadoValidacion result = validationResults.get(0);
        List<DatosNodosFirmados> signedNodes = result.getDatosFirma().getDatosNodosFirmados();
        for (DatosNodosFirmados signedData : signedNodes) {
            try {
                bos.write(signedData.getNodoFirmadoBytes());
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                return null;
            }
        }
        // TODO Auto-generated method stub
        return digestAlgorithm.digest(bos.toByteArray());
    }

    /*
     * Genera una firma (parserizzando le controfirme contenute)
     */
    private ISignature getISignatureFromResultadoValidacionAndXMLSignature(ResultadoValidacion validationResult) {
        // if (this.type == SignerType.XML_DSIG) {
        //
        // org.apache.xml.security.signature.XMLSignature xml = validationResult.getXmlSignature();
        // X509Certificate certificate;
        // try {
        // certificate = xml.getKeyInfo().getX509Certificate();
        // } catch (KeyResolverException ex) {
        // return null;
        // }
        //
        //
        // DOMValidateContext context = new DOMValidateContext(certificate.getPublicKey(), validationResult.getDoc());
        // XAdESSignature signature = new XAdESSignature(validationResult.getXmlSignature(), context, certificate,
        // validationResult,
        // SignerType.XML_DSIG);
        //
        // List<ResultadoValidacion> counterSignaturesResults = validationResult.getContrafirmadoPor();
        // if (counterSignaturesResults != null) {
        // List<ISignature> counterSignatures = new ArrayList<ISignature>();
        // for (ResultadoValidacion counterSignatureResult : counterSignaturesResults) {
        // ISignature counterSignature = getISignatureFromResultadoValidacionAndXMLSignature(counterSignatureResult);
        // counterSignatures.add(counterSignature);
        // }
        // signature.setCounterSignatures(counterSignatures);
        // }
        // return signature;
        //
        // } else {
        Certificate certificate = validationResult.getDatosFirma().getCadenaFirma() != null
                ? validationResult.getDatosFirma().getCadenaFirma().getCertificates().get(0) : null;
        if (certificate == null) {
            org.apache.xml.security.signature.XMLSignature xml = validationResult.getXmlSignature();
            try {
                certificate = xml.getKeyInfo().getX509Certificate();
            } catch (KeyResolverException ex) {
                return null;
            }
        }
        if (certificate instanceof X509Certificate) {
            DOMValidateContext context = new DOMValidateContext(certificate.getPublicKey(), validationResult.getDoc());
            XAdESSignature signature = new XAdESSignature(validationResult.getXmlSignature(), context,
                    (X509Certificate) certificate, validationResult,
                    enumFormatoFirma2SignerType(validationResult.getDatosFirma().getTipoFirma().getTipoXAdES()));

            List<ResultadoValidacion> counterSignaturesResults = validationResult.getContrafirmadoPor();
            if (counterSignaturesResults != null) {
                List<ISignature> counterSignatures = new ArrayList<ISignature>();
                for (ResultadoValidacion counterSignatureResult : counterSignaturesResults) {
                    ISignature counterSignature = getISignatureFromResultadoValidacionAndXMLSignature(
                            counterSignatureResult);
                    counterSignatures.add(counterSignature);
                }
                signature.setCounterSignatures(counterSignatures);
            }
            return signature;
        }
        return null;
        // }
    }

    public List<ISignature> getSignatures() {

        List<ISignature> signatures = new ArrayList<ISignature>();
        int i = 0;
        if (xmlSignatures == null) {
            return signatures;
        } else {
            for (ResultadoValidacion validationResult : validationResults) {

                // La getISignatureFromResultadoValidacionAndXMLSignature è da invocare solo se la firma non è una
                // controfirma, quindi faccio una verifica
                if (validationResult.getDatosFirma().getContraFirma() == null
                        || validationResult.getDatosFirma().getContraFirma().isEmpty()) {
                    ISignature signature = getISignatureFromResultadoValidacionAndXMLSignature(validationResult);
                    if (signature != null) {
                        signatures.add(signature);
                    }
                }
                // Certificate certificate = validationResult.getDatosFirma().getCadenaFirma().getCertificates().get(0);
                // if (certificate instanceof X509Certificate){
                // DOMValidateContext context = new DOMValidateContext(certificate.getPublicKey(), doc);
                // XAdESSignature xadesSignature = new XAdESSignature(xmlSignature, context,
                // (X509Certificate)certificate);
                // signatures.add(xadesSignature);
                // }
            }
        }
        return signatures;
    }

    public boolean canContentBeSigned() {
        return false;
    }

    public Collection<CRL> getEmbeddedCRLs() {
        // TODO Auto-generated method stub
        return null;
    }

    public Collection<? extends Certificate> getEmbeddedCertificates() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public SignerType getTimeStampFormat() {
        return SignerType.XADES_T;
    }

    private boolean isXmlDigSig(ValidationInfos complianceCheck) {

        try {
            NodeList signatureNodesList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (signatureNodesList.getLength() == 0) {
                complianceCheck.addWarning("Impossibile trovare il nodo Signature");
                throw new Exception("Cannot find Signature element");
            }
            for (int i = 0; i < signatureNodesList.getLength(); i++) {

                Node signatureNode = signatureNodesList.item(i);

                XMLSignatureFactory factory = MyDOMXMLSignatureFactory.getInstance("DOM", "MyXMLDSig");
                DOMStructure struct = new DOMStructure(signatureNode);

                XMLSignature xmlSignature = factory.unmarshalXMLSignature(struct);

                try {
                    getX509Certificate(xmlSignature);
                } catch (Exception e) {
                    complianceCheck.addWarning(e.getMessage());
                    throw e;
                }

                if (signatureNode instanceof Element) {
                    Element signatureNodeElement = (Element) signatureNode;
                    if (xmlSignatures == null) {
                        xmlSignatures = new ArrayList<XMLSignature>();
                    }
                    this.type = SignerType.XML_DSIG;
                    xmlSignatures.add(xmlSignature);
                }
            }
        } catch (Exception e) {
            // Nonostante sia stato generato un errore, può
            // comunque essere una firma di tipo XAdES in quanto
            // si può trattare di un errore di decodifica di una parte
            // nel caso il tipo di formato sia stato rilevato, restituisco
            // comunque true
            if (this.type != null) {
                return true;
            } else {
                return false;
            }

        }
        return this.type != null && xmlSignatures != null;
    }

    private KeyInfo getKeyInfo(XMLSignature xmlSignature) throws Exception {
        if (xmlSignature != null) {
            return xmlSignature.getKeyInfo();
        }
        throw new Exception("Impossibile trovare un nodo KeyInfo all'interno della firma xml");
    }

    private X509Data getX509Data(XMLSignature xmlSignature) throws Exception {
        KeyInfo keyInfo = getKeyInfo(xmlSignature);
        if (keyInfo != null) {
            for (Object o1 : keyInfo.getContent()) {
                if (o1 instanceof X509Data) {
                    return (X509Data) o1;
                }
            }
        }
        throw new Exception("Impossibile trovare un nodo X509Data all'interno del nodo KeyInfo della firma xml");
    }

    private X509Certificate getX509Certificate(XMLSignature xmlSignature) throws Exception {
        X509Data x509Data = getX509Data(xmlSignature);
        if (x509Data != null) {
            for (Object o1 : x509Data.getContent()) {
                if (o1 instanceof X509Certificate) {
                    return (X509Certificate) o1;
                }
            }
        }
        throw new Exception("Impossibile trovare un nodo certificato all'interno del nodo KeyInfo della firma xml");
    }

    public ParserPool getParserPool() {
        return parserPool;
    }

    public void setParserPool(ParserPool parserPool) {
        this.parserPool = parserPool;
    }
}
