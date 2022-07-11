package it.eng.crypto.data;

import it.eng.crypto.CryptoConfiguration;
import it.eng.crypto.CryptoConstants;
import it.eng.crypto.CryptoSingleton;
import it.eng.crypto.context.CryptoSignerApplicationContextProvider;
import it.eng.crypto.exception.CryptoSignerException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.impl.client.DefaultHttpClient;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.X509Principal;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.w3c.dom.Document;

import be.fedict.eid.tsl.TrustService;
import be.fedict.eid.tsl.TrustServiceList;
import be.fedict.eid.tsl.TrustServiceListFactory;
import be.fedict.eid.tsl.TrustServiceProvider;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.parser.PdfReaderContentParser;
import com.itextpdf.text.pdf.parser.SimpleTextExtractionStrategy;
import com.itextpdf.text.pdf.parser.TextExtractionStrategy;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.data.type.SignerType;
import it.eng.crypto.storage.ICAStorage;

import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.naming.NameNotFoundException;
import javax.security.auth.x500.X500Principal;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.w3c.dom.DOMException;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class SignerUtil {

    public enum EnumSigner {

        CMSSigner, M7MSigner, P7MSigner, PdfSigner, TsrSigner, XMLSigner
    }

    Logger log = LoggerFactory.getLogger(SignerUtil.class);
    private ApplicationContext context;

    private SignerUtil(ApplicationContext applicationContext) {
        context = applicationContext;
        if (context == null) {
            context = new ClassPathXmlApplicationContext("VerificheControllerConfig.xml");
        }
        CryptoSingleton.getInstance().setContext(context);
    }

    /**
     * Crea una nuova istanza della classe
     *
     * @return nuova istanza della classe
     */
    public static SignerUtil newInstance() {
        return new SignerUtil(CryptoSignerApplicationContextProvider.getContext());
    }

    /**
     * Crea una nuova istanza della classe con un applicationContext specifico
     *
     * @param applicationContext
     *            Spring applicationContext
     *
     * @return nuova istanza della classe
     */
    public static SignerUtil newInstance(ApplicationContext applicationContext) {
        return new SignerUtil(applicationContext);
    }

    /**
     * Recupera l'{@link it.eng.crypto.data.AbstractSigner} preposto al riconoscimento del file firmato in input
     *
     * @param file
     *            il file firmato di cui ricavare il signer
     *
     * @return l'{@link it.eng.crypto.data.AbstractSigner} da utilizzare
     *
     * @throws CryptoSignerException
     */
    public AbstractSigner getSignerManager(File file) throws CryptoSignerException {
        // Controllo che tipo di Signer Utilizzare
        Map<String, ValidationInfos> complianceChecks = null;
        DataSigner dataSigner = context.getBean("DataSigner", DataSigner.class);
        for (AbstractSigner signer : dataSigner.getSignersManager()) {

            // AbstractSigner newSigner = signer.getClass().newInstance();
            ValidationInfos vi = new ValidationInfos();
            if (signer.isSignedType(file, vi)) {
                signer.setFile(file);
                return signer;
            }
            // aggiungo alla mappa i controlli di conformità
            if (!vi.isValid(true)) {
                if (complianceChecks == null) {
                    complianceChecks = new HashMap<String, ValidationInfos>();
                }
                complianceChecks.put(signer.getClass().getSimpleName(), vi);
            }

        }
        // Se sono arrivato fino a qui lancio una eccezione;
        throw new CryptoSignerException("Nessun Manager Signer Trovato per il file specificato: " + file,
                complianceChecks);

    }

    /**
     * Ritorna l'AuthorityKeyIdentifier del certificato passato in input
     *
     * @param crl,
     *            CRL
     *
     * @return auth key id della CRL
     *
     * @throws IOException
     *             in caso di errore
     */
    public static String getAuthorityKeyId(X509CRL crl) throws IOException {
        byte[] extvalue = crl.getExtensionValue("2.5.29.35");
        if (extvalue == null) {
            return null;
        }
        DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(extvalue)).readObject());
        AuthorityKeyIdentifier keyId = new AuthorityKeyIdentifier(
                (ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(oct.getOctets())).readObject());
        byte[] authkeyId = keyId.getKeyIdentifier(); // new
        // AuthorityKeyIdentifierStructure(pkcs7.getSigningCertificate()).getKeyIdentifier();
        return Hex.encodeHexString(authkeyId);
    }

    /**
     * Ritorna l'AuthorityKeyIdentifier del certificato passato in input
     *
     * @param cert,
     *            certificato
     *
     * @return auth key id del certificato
     *
     * @throws IOException
     *             in caso di errore
     */
    public static String getAuthorityKeyId(X509Certificate cert) throws IOException {
        byte[] extvalue = cert.getExtensionValue("2.5.29.35");
        if (extvalue == null) {
            return null;
        }
        DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(extvalue)).readObject());
        AuthorityKeyIdentifier keyId = new AuthorityKeyIdentifier(
                (ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(oct.getOctets())).readObject());
        byte[] authkeyId = keyId.getKeyIdentifier(); // new
        // AuthorityKeyIdentifierStructure(pkcs7.getSigningCertificate()).getKeyIdentifier();
        return Hex.encodeHexString(authkeyId);
    }

    /**
     * Ritorna il SubjectKeyIdentifier del certificato passato in input
     *
     * @param cert,
     *            certificato
     *
     * @return subject keu id del certificato
     *
     * @throws IOException
     *             in caso di errore
     */
    public static String getSubjectKeyId(X509Certificate cert) throws IOException {
        byte[] extvalue = cert.getExtensionValue("2.5.29.14");
        if (extvalue == null) {
            return null;
        }
        ASN1OctetString str = ASN1OctetString
                .getInstance(new ASN1InputStream(new ByteArrayInputStream(extvalue)).readObject());
        SubjectKeyIdentifier keyId = SubjectKeyIdentifier
                .getInstance(new ASN1InputStream(new ByteArrayInputStream(str.getOctets())).readObject());
        byte[] subjKeyId = keyId.getKeyIdentifier();
        return Hex.encodeHexString(subjKeyId);

    }

    /**
     * Controlla se il certificato passato in ingresso è valido per la CRL associata
     *
     * @param certificate,
     *            certificato
     * @param crl,
     *            CRL
     *
     * @return true se valido
     *
     * @throws CryptoSignerException
     *             in caso di errore
     */
    public boolean validCertificateWithCRL(java.security.cert.X509Certificate certificate, X509CRL crl)
            throws CryptoSignerException {
        boolean isValid = false;
        try {
            certificate.checkValidity();
            if (!crl.isRevoked(certificate)) {
                isValid = true;
            }
        } catch (CertificateExpiredException e) {
            log.error("Certificato scaduto", e);
        } catch (CertificateNotYetValidException e) {
            log.error("Certificato non ancora valido", e);
        }
        return isValid;
    }

    /**
     * Recupera la CRL in base all'url passato in ingresso
     *
     * @param urls,
     *            lista di indirizzi delle CRL
     *
     * @return oggetto CRL
     *
     */
    public X509CRL getCrlByURL(List<String> urls) {

        X509CRL mostRecentCrl = null;
        for (String url : urls) {
            X509CRL crl = null;
            try {
                CRLUtil util = new CRLUtil();

                url = StringUtils.trim(url);
                log.info("Scarico la CRL dall'URL: " + url);
                if (url.toUpperCase().startsWith("LDAP")) {
                    crl = util.searchCrlByLDAP(url);
                } else if (url.toUpperCase().startsWith("HTTP")) {
                    crl = util.ricercaCrlByProxyHTTP(url, CryptoSingleton.getInstance().getConfiguration());
                } else {
                    throw new CryptoSignerException("Protocollo di comunicazione non supportato!");
                }
                // log.info("getCrlByURL END");
                log.info("CRL scaricata correttamente");
            } catch (CryptoSignerException e) {
                log.warn("Si è verificato il seguente errore: " + e.toString() + ", "
                        + (e.getCause() != null ? e.getCause().toString() : ""));
            } catch (NameNotFoundException e) {
                log.error("Si è verificato il seguente errore: " + e.toString() + ", " + e.getMessage() + ", "
                        + (e.getCause() != null ? e.getCause().getMessage() : ""));

            } catch (Exception e) {
                log.error("Si è verificato il seguente errore: " + e.toString() + ", " + e.getMessage() + ", "
                        + (e.getCause() != null ? e.getCause().getMessage() : ""), e);
            }
            if (crl != null && (mostRecentCrl == null || mostRecentCrl.getNextUpdate().before(crl.getNextUpdate()))) {
                mostRecentCrl = crl;
            }
        }
        return mostRecentCrl;
    }

    /**
     * Recupera un vettore contenente i distribution point CRL del certificato passato in ingresso
     *
     * @param certificate,
     *            certificato
     *
     * @return Lista di Distribution point delle CRL
     *
     * @throws CryptoSignerException
     *             in caso di errore
     */
    public List<String> getURLCrlDistributionPoint(X509Certificate certificate) throws CryptoSignerException {
        ASN1InputStream oAsnInStream = null;
        ASN1InputStream oAsnInStream2 = null;
        try {
            byte[] val1 = certificate.getExtensionValue("2.5.29.31");
            oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(val1));
            DERObject derObj = oAsnInStream.readObject();
            DEROctetString dos = (DEROctetString) derObj;
            byte[] val2 = dos.getOctets();
            oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(val2));
            DERObject derObj2 = oAsnInStream2.readObject();
            CRLUtil util = new CRLUtil();
            Vector<String> urls = (Vector<String>) util.getDERValue(derObj2);
            if (urls != null && !urls.isEmpty()) {
                return new ArrayList<String>(urls);
            } else {
                throw new Exception("Lista delle distribution point vuota o nulla");
            }
        } catch (Exception e) {
            throw new CryptoSignerException("Errore nel recupero del distribution point della CRL", e);
        } finally {
            IOUtils.closeQuietly(oAsnInStream);
            IOUtils.closeQuietly(oAsnInStream2);
        }
    }

    private HttpResponse doGet(String urlString) throws IOException {
        CryptoConfiguration cryptoConfiguration = context.getBean(CryptoConstants.CRYPTO_CONFIGURATION,
                CryptoConfiguration.class);

        HttpGet method = new HttpGet(urlString);

        DefaultHttpClient httpclient = new DefaultHttpClient();
        if (cryptoConfiguration.isProxy()) {
            Credentials credential = cryptoConfiguration.isNTLSAuth()
                    ? new NTCredentials(cryptoConfiguration.getProxyUser(), cryptoConfiguration.getProxyPassword(),
                            cryptoConfiguration.getUserHost(), cryptoConfiguration.getUserDomain())
                    : new UsernamePasswordCredentials(cryptoConfiguration.getProxyUser(),
                            cryptoConfiguration.getProxyPassword());
            HttpHost proxy = new HttpHost(cryptoConfiguration.getProxyHost(), cryptoConfiguration.getProxyPort());
            httpclient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
            httpclient.getCredentialsProvider().setCredentials(new AuthScope(proxy.getHostName(), proxy.getPort()),
                    credential);
        }
        return httpclient.execute(method);

    }

    private void addCertificateFromList(String localTrustedListUrl,
            Map<String, X509Certificate> qualifiedCertificates) {
        boolean isPdf = false;
        HttpEntity entity = null;
        try {
            HttpResponse httpResponse = doGet(localTrustedListUrl);
            entity = httpResponse.getEntity();
            if (entity == null) {
                // non posso far nulla se l'entity http non è compilata
                return;
            }
            Header contentType = entity.getContentType();
            if (contentType != null) {
                isPdf = contentType.getValue().equals("application/pdf");
            }
        } catch (IOException ex) {
            log.warn("Errore nel parsing della Trusted list: ", ex);
        }
        if (entity == null) {
            // non posso far nulla se l'entity http non è compilata
            return;
        }
        try (InputStream is = entity.getContent()) {
            if (isPdf) {
                addCertificateFromPdfList(qualifiedCertificates, is);
            } else {
                addCertificateFromXmlList(qualifiedCertificates, is);
            }
        } catch (IOException | CryptoSignerException ex) {
            log.warn("Errore nel parsing della Trusted list: ", ex);
        }

    }

    private void addCertificateFromXmlList(Map<String, X509Certificate> qualifiedCertificates, InputStream xmlStream)
            throws CryptoSignerException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder docBuilder = factory.newDocumentBuilder();

            Document docTsl = docBuilder.parse(xmlStream);
            addCertificateFromXmlList(qualifiedCertificates, docTsl);

        } catch (IOException | ParserConfigurationException | SAXException ex) {

            throw new CryptoSignerException("Errore nel parsing dell'XML della Trusted list: ", ex);
        }
    }

    private void addCertificateFromXmlList(Map<String, X509Certificate> qualifiedCertificates, Document docTsl)
            throws CryptoSignerException {
        List<TrustServiceProvider> trustServiceProviders = null;
        try {

            TrustServiceList trustServiceList = TrustServiceListFactory.newInstance(docTsl);
            trustServiceProviders = trustServiceList.getTrustServiceProviders();

        } catch (IOException ex) {

            throw new CryptoSignerException("Errore nel parsing dell'XML della Trusted list: ", ex);
        }

        for (TrustServiceProvider trustServiceProvider : trustServiceProviders) {
            try {

                List<TrustService> trustServices = trustServiceProvider.getTrustServices();
                int idx = 0;
                final int allCerts = trustServices.size();
                for (TrustService trustService : trustServices) {
                    X509Certificate certificate = trustService.getServiceDigitalIdentity();
                    log.debug("TSP {}/{}: {} / Service: {} / Status: {}", (++idx), allCerts,
                            trustServiceProvider.getName(), trustService.getName(), trustService.getStatus());
                    qualifiedCertificates.put(
                            certificate.getSubjectX500Principal().getName() + "|" + getSubjectKeyId(certificate),
                            certificate);
                }
            } catch (IOException | RuntimeException ex) {
                log.warn("Errore durante la crezione del certificato presente nel TSP in formato XML. Continuo.", ex);
            }
        }
    }

    private void addCertificateFromPdfList(Map<String, X509Certificate> qualifiedCertificates, InputStream pdfStream)
            throws CryptoSignerException {
        PdfReader pdf = null;
        PdfReaderContentParser parser = null;
        try {
            pdf = new PdfReader(pdfStream);
            parser = new PdfReaderContentParser(pdf);
        } catch (IOException ex) {
            throw new CryptoSignerException("Errore nel parsing dell PDF della Trusted list: ", ex);
        }

        List<String> allPem = new ArrayList<>();

        for (int i = 1; i <= pdf.getNumberOfPages(); i++) {
            try {
                TextExtractionStrategy strategy = parser.processContent(i, new SimpleTextExtractionStrategy());
                String resultantText = strategy.getResultantText();

                String[] stringArray = StringUtils.substringsBetween(resultantText, "-----BEGIN CERTIFICATE-----",
                        "-----END CERTIFICATE-----");
                if (stringArray != null && stringArray.length > 0) {
                    for (String certificate : stringArray) {
                        allPem.add(certificate.replaceAll("\\s+", ""));
                    }

                }
            } catch (IOException ex) {
                log.warn("Errore durante l'estrazione del PEM del certificato nel TSP in formato PDF dalla pagina {}",
                        i, ex);
            }
        }
        int idx = 0;
        final int allCerts = allPem.size();
        for (String pem : allPem) {

            byte[] certificateBytes = null;
            try {
                certificateBytes = Base64.getDecoder().decode(pem);

            } catch (IllegalArgumentException ex) {
                log.warn("Errore durante la lettura del base64 del certificato nel TSP in formato PDF", ex);
            }

            if (certificateBytes != null) {

                try (InputStream in = new ByteArrayInputStream(certificateBytes);) {
                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(in);
                    log.debug("TSP {}/{} in formato PDF: {}", (++idx), allCerts,
                            certificate.getSubjectX500Principal().getName());
                    qualifiedCertificates.put(
                            certificate.getSubjectX500Principal().getName() + "|" + getSubjectKeyId(certificate),
                            certificate);
                } catch (IOException | CertificateException | RuntimeException ex) {
                    log.warn("Errore durante la crezione del certificato presente nel TSP in formato PDF.Continuo.",
                            ex);
                }
            }
        }
    }

    public static void main(String[] args) throws CryptoSignerException {
        SignerUtil me = newInstance();
        Map<String, X509Certificate> qualifiedPrincipalsAndX509Certificates = me
                .getQualifiedPrincipalsAndX509Certificates();

        qualifiedPrincipalsAndX509Certificates.forEach((key, value) -> System.out.println(key + " " + value));
    }

    /**
     * Recupera la lista dei certificati accreditati dalla Trust Service Status List (ETSI TS 102 231) configurata nel
     * contesto Spring all'interno del bean "CryptoConfiguration" come attributo QualifiedCertificatesURL.
     *
     * @return la mappa delle corrispondenze tra Principal (ente) e certificato
     *
     * @throws CryptoSignerException
     *             in caso di errore
     */
    public Map<String, X509Certificate> getQualifiedPrincipalsAndX509Certificates() throws CryptoSignerException {
        final long start = System.currentTimeMillis();
        Map<String, X509Certificate> qualifiedCertificates = new HashMap<String, X509Certificate>();
        HttpResponse response = null;
        String urlString = null;
        try {
            CryptoConfiguration cryptoConfiguration = context.getBean(CryptoConstants.CRYPTO_CONFIGURATION,
                    CryptoConfiguration.class);

            urlString = cryptoConfiguration.getQualifiedCertificatesURL();
            response = doGet(urlString);
        } catch (BeansException | IOException e) {
            throw new CryptoSignerException("Errore nel recupero dei certificati accreditati: ", e);
        }
        try (InputStream is = response.getEntity().getContent();) {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder docBuilder = factory.newDocumentBuilder();
            Document mainLotl = docBuilder.parse(is);
            NodeList trustServiceProviderList = mainLotl.getElementsByTagName("TrustServiceProviderList");
            // Se non è una TSL è una LOTL (List Of Trusted List, usato da EIDAS)
            boolean isTSL = trustServiceProviderList.getLength() > 0;
            if (isTSL) {
                log.info("L'URL principale è una TSL: {}", urlString);
                addCertificateFromXmlList(qualifiedCertificates, mainLotl);

            } else {
                NodeList tslLocations = mainLotl.getElementsByTagName("TSLLocation");
                for (int i = 0; i < tslLocations.getLength(); i++) {
                    log.info("L'URL principale è una LOTL: {}", urlString);
                    log.debug("LOTL: Recuperata lista {}/{}", (i + 1), tslLocations.getLength());
                    Node tslLocation = tslLocations.item(i);
                    String localTsl = tslLocation.getTextContent();
                    addCertificateFromList(localTsl, qualifiedCertificates);
                }
            }

        } catch (IOException | SAXException | DOMException | ParserConfigurationException ex) {
            throw new CryptoSignerException("Errore nel recupero dei certificati accreditati: ", ex);
        } finally {
            log.info("Recuperate tutte le CA accreditate in  " + (System.currentTimeMillis() - start) + " ms");
        }
        return qualifiedCertificates;
    }

    /**
     * Ottiene il certificato della CA se è presente nella Trust Service Status List (ETSI TS 102 231) .Effettua questa
     * ricerca come fallback nel caso il db delle CA non sia ancora stato popolato.<em>Attenzione:</em> tutti i
     * controlli che vengono effettuati avvengono interrogando la rete.
     *
     * La riceca ha esito positivo se:
     * <ul>
     * <li>l'<em>issuer principal</em> del certificato passato in input corrisponde all'<em>issuer principal</em> del
     * certificato qualificato</li>
     * <li>l'<em>authorityKeyID</em> del certificato passato in input corrisponde al <em>subjectKeyID</em> del
     * certificato qualificato.</li>
     * </ul>
     *
     * @param signingCertificate
     *            certificato del firmatario da verificare con la lista delle CA accreditate
     * @param certificatesAuthorityStorage
     *            interfaccia per salvare il dato sul DB
     *
     * @return Certificato della CA oppure NULL
     */
    public X509Certificate getCACertificateOnline(X509Certificate signingCertificate,
            ICAStorage certificatesAuthorityStorage) {
        try {
            final String authIdSignature = getAuthorityKeyId(signingCertificate);
            log.debug("Ricerca online della CA/TSA per il certificato con principal "
                    + signingCertificate.getIssuerX500Principal().getName() + " e auth key ID " + authIdSignature);

            Map<String, X509Certificate> qualifiedCertificates = getQualifiedPrincipalsAndX509Certificates();
            for (X509Certificate donwloadedCaCert : qualifiedCertificates.values()) {
                try {
                    certificatesAuthorityStorage.insertCA(donwloadedCaCert);
                } catch (Exception ignore) {
                    log.debug("Errore durante l'inserimento della CA ", ignore);
                }
                X500Principal issuerPrincipal = signingCertificate.getIssuerX500Principal();
                if (donwloadedCaCert.getIssuerX500Principal().getName().equals(issuerPrincipal.getName())) {
                    String subjectKeyId = getSubjectKeyId(donwloadedCaCert);
                    if (authIdSignature.equals(subjectKeyId)) {
                        // qualifiedCertificate = donwloadedCaCert;
                        return donwloadedCaCert;
                    }
                }

            }
        } catch (CryptoSignerException | IOException e) {
            log.debug("Errore durante il recupero del certificato dalla rete", e);
        }

        return null;
    }

    /**
     * Metodo di utilità che consente di trasformare il contenuto in byte in input nella corrispondente stringa
     * esadecimale
     *
     * @param buf
     *            contenuto in byte
     *
     * @return la stringa esadecimale corrispondente al contenuto
     */
    public static String asHex(byte buf[]) {
        StringBuilder strbuf = new StringBuilder(buf.length * 2);

        for (int i = 0; i < buf.length; i++) {
            if (((int) buf[i] & 0xff) < 0x10) {
                strbuf.append("0");
            }
            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }
        return strbuf.toString();
    }

    public static X509Certificate getCertificateFromCollection(Principal issuerPrincipal,
            Collection<? extends Certificate> certificates) {
        X500Name x500Name = new X500Name(issuerPrincipal.getName());
        synchronized (x500Name) {
            if (certificates != null) {
                for (Certificate qualifiedCertificate : certificates) {
                    if (qualifiedCertificate instanceof X509Certificate) {
                        X509Certificate x509Certificate = (X509Certificate) qualifiedCertificate;
                        Principal principal = x509Certificate.getSubjectX500Principal();
                        if (principal instanceof X509Principal) {
                            X509Principal x509Principal = (X509Principal) principal;
                            if (x509Principal.equals(x500Name)) {
                                return x509Certificate;
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    /*
     * Utilizzato per calcolare il formato in caso di firme non conformi
     */
    public static final SignerType enumSigner2SignerType(String formatoFirma) {

        if (formatoFirma.equals("CMSSigner")) {
            return SignerType.P7M;
        }
        if (formatoFirma.equals("M7MSigner")) {
            return SignerType.M7M;
        }
        if (formatoFirma.equals("P7MSigner")) {
            return SignerType.P7M;
        }
        if (formatoFirma.equals("PdfSigner")) {
            return SignerType.PDF_DSIG;
        }
        if (formatoFirma.equals("TsrSigner")) {
            return SignerType.TSR;
        }
        if (formatoFirma.equals("XMLSigner")) {
            return SignerType.XML_DSIG;
        }

        return null;

    }
}
