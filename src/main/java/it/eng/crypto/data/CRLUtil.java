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

package it.eng.crypto.data;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Vector;

import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.eng.crypto.CryptoConfiguration;
import it.eng.crypto.exception.CryptoSignerException;

public class CRLUtil {

    private static final Logger LOG = LoggerFactory.getLogger(CRLUtil.class.getName());

    private static final String X509 = "X.509";
    private static final String BC_PROVIDER = "BC";

    /**
     *  Recupera le CRL tramite il protocollo HTTP/HTTPS con supporto proxy
     * 
     * @param url URL della CRL
     * @param configuration Configurazione della connessione
     * @param httpTimeoutConnection timeout di connessione HTTP
     * @param httpSocketTimeout timeout di socket HTTP
     * @return CRL recuperata
     * @throws IOException generica eccezione di I/O
     * @throws CryptoSignerException generica eccezione di firma
     * @throws CertificateException generica eccezione di certificato
     * @throws NoSuchProviderException generica eccezione di provider non trovato
     */
    X509CRL ricercaCrlByProxyHTTP(String url, CryptoConfiguration configuration, int httpTimeoutConnection, int httpSocketTimeout) throws IOException,
            CryptoSignerException, CertificateException, NoSuchProviderException {

        final int connectionTimeout = httpTimeoutConnection * 1000; // conversione in millisecondi
        final int socketTimeout = httpSocketTimeout * 1000; // conversione in millisecondi
        RequestConfig.Builder requestConfigBuilder = RequestConfig.custom()
                .setConnectTimeout(connectionTimeout).setSocketTimeout(socketTimeout);

        CredentialsProvider credsProvider = new BasicCredentialsProvider();

        if (configuration.isProxy()) {
            HttpHost proxy = new HttpHost(configuration.getProxyHost(),
                    configuration.getProxyPort());
            requestConfigBuilder.setProxy(proxy);

            Credentials credential = configuration.isNTLSAuth()
                    ? new NTCredentials(configuration.getProxyUser(),
                            configuration.getProxyPassword(), configuration.getUserHost(),
                            configuration.getUserDomain())
                    : new UsernamePasswordCredentials(configuration.getProxyUser(),
                            configuration.getProxyPassword());
            credsProvider.setCredentials(new AuthScope(proxy.getHostName(), proxy.getPort()),
                    credential);
        }

        RequestConfig requestConfig = requestConfigBuilder.build();

        try (CloseableHttpClient httpclient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig).setDefaultCredentialsProvider(credsProvider)
                .build()) {

            byte[] content = executeHttpRequest(httpclient, new HttpPost(url));
            if (content == null || content.length == 0) {
                content = executeHttpRequest(httpclient, new HttpGet(url));
            }
            if (content != null && content.length != 0) {
                return parse(content);
            } else {
                throw new CryptoSignerException(
                        "Il server non ha restituito alcun dato per la CRL dall'URL: " + url);
            }
        } catch (IOException e) {
            throw new CryptoSignerException("La connessione è stata interrotta per un errore", e);
        }
    }

    private byte[] executeHttpRequest(CloseableHttpClient httpclient, HttpUriRequest request)
            throws IOException, CryptoSignerException {
        try (CloseableHttpResponse httpResponse = httpclient.execute(request)) {
            HttpEntity entity = httpResponse.getEntity();
            int statusCode = httpResponse.getStatusLine().getStatusCode();
            if (statusCode == HttpURLConnection.HTTP_OK) {
                return EntityUtils.toByteArray(entity);
            } else {
                EntityUtils.consume(entity);
                if (request instanceof HttpPost) {
                    ((HttpPost) request).abort();
                    return null;
                } else {
                    throw new CryptoSignerException("The server returned code: " + statusCode);
                }
            }
        }
    }

    /**
     * Recupera le CRL tramite il protocollo LDAP
     *
     * @param url
     * @param ldapTimeoutConnection 
     *
     * @return
     * @throws IOException 
     * @throws NoSuchProviderException 
     * @throws CertificateException 
     * @throws CryptoSignerException 
     *
     * @throws Exception
     */
    X509CRL searchCrlByLDAP(String url, int ldapTimeoutConnection) throws CertificateException, NoSuchProviderException, IOException, CryptoSignerException {
        final String timeout = String.valueOf(ldapTimeoutConnection * 1000); // conversione in millisecondi
        String ldapUrl = url.replace(" ", "%20");
        X509CRL ret = null;
        if (ldapUrl.toLowerCase().indexOf("?certificaterevocationlist") < 0) {
            ldapUrl = ldapUrl + "?certificaterevocationlist";
        }
        Map<String, String> env = new HashMap<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl);
        env.put("com.sun.jndi.ldap.read.timeout", timeout);
        env.put("com.sun.jndi.ldap.connect.pool.timeout", timeout);
        env.put("com.sun.jndi.ldap.connect.timeout", timeout);
        DirContext ctx = null;
        NamingEnumeration<? extends Attribute> ae = null;
        try {
            ctx = new InitialDirContext(new Hashtable<>(env));
            Attributes attribs = ctx.getAttributes("");
            ae = attribs.getAll();
            while (ae.hasMore()) {
                Attribute a = ae.next();
                if (a.getID() != null
                        && a.getID().toLowerCase().indexOf("certificaterevocationlist") != -1) {
                    ret = parse((byte[]) a.get(0));
                    break;
                }
            }

        } catch (CommunicationException ex) {
            throw new CryptoSignerException("Errore di comunicazione con la CA", ex);
        } catch (NamingException ex) {
            throw new CryptoSignerException("Errore di comunicazione con la CA", ex);
        } finally {
            if (ae != null) {
                try {
                    ae.close();
                } catch (Exception e) {
                    LOG.error("Unable to close LDAP Attributes: {}", e.getMessage());
                }
            }
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (Exception e) {
                    LOG.error("Unable to close LDAP Context {}", e.getMessage());
                }
            }
        }

        return ret;
    }

    X509CRL ricercaCrlByFile(String url) throws URISyntaxException, IOException, CertificateException, NoSuchProviderException {
        Path crlPath = Paths.get(new URI(url));
        byte[] crlBytes = Files.readAllBytes(crlPath);
        return parse(crlBytes);

    }

    // ******************************************************************************************************************************
    // Metodi di utilità
    // ******************************************************************************************************************************
    /**
     * Parsa l'array di byte in ingresso per recuperare la CRL
     *
     * @param crlEnc byte array della crl così come fornito dall'url
     *
     * @return crl o null
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchProviderException
     */
    public static X509CRL parse(byte[] crlEnc)
            throws CertificateException, IOException, NoSuchProviderException {
        X509CRL crl = null;
        if (crlEnc == null) {
            return crl;
        }
        boolean probablyBase64 = false;
        byte[] crlData;
        try {
            crlData = Base64.decode(crlEnc);
            probablyBase64 = true;
        } catch (Exception e) {
            crlData = crlEnc;
            LOG.debug("CRL non in formato Base64");
        }
        boolean tryBCProvider = false;
        try {
            crl = generateCRL(crlData);
        } catch (CRLException e) {
            tryBCProvider = true;
            LOG.debug("CRL non parsabile con provider Java, provo con BouncyCastle Errore: {}",
                    e.getMessage());
        }

        if (tryBCProvider) {
            try {
                crl = generateCRLWithBouncyCastle(crlData);
            } catch (CRLException e) {
                LOG.debug("CRL non parsabile con provider BouncyCastle Errore: {}", e.getMessage());
            }
        }
        // ultima speranza, provo a "riparare" il byte array originale
        if (crl == null && probablyBase64) {
            crl = repairCRLBase64(crlEnc);
        }

        return crl;
    }

    /**
     * In alcuni casi il base64 decoder di BC non è in grado di interpretare il base64 del
     * certificato perché presentato su più righe. In questo caso elimino i caratteri di fine linea
     * (e il boundary del ascii armor) ed utilizzo il decoder standard di java.
     *
     * @param crlEnc CRL in formato base64
     *
     * @return oggetto CRL (o null)
     */
    private static X509CRL repairCRLBase64(byte[] crlEnc) {
        X509CRL crl = null;
        try {
            String lastHope = new String(crlEnc, StandardCharsets.UTF_8).replaceAll("[\\n\\r]", "")
                    .replace("-----BEGIN X509 CRL-----", "").replace("-----END X509 CRL-----", "");
            byte[] hope = lastHope.getBytes(StandardCharsets.UTF_8);
            byte[] crlData = java.util.Base64.getDecoder().decode(hope);
            boolean tryBCProvider = false;
            try {
                crl = generateCRL(crlData);

            } catch (CRLException e) {
                tryBCProvider = true;
                LOG.debug("CRL non parsabile con provider Java, provo con BouncyCastle Errore: {}",
                        e.getMessage());
            }

            if (tryBCProvider) {
                crl = generateCRLWithBouncyCastle(crlData);
            }

        } catch (Exception e) {
            LOG.debug("Errore nella conversione (ultima speranza)", e);
        }
        return crl;
    }

    /**
     * Ottieni la CRL utilizzando il provider X.509 predefinito di Java.
     *
     * @param crlData CRL in forma binaria (DER)
     *
     * @return oggetto crl o null
     *
     * @throws CRLException         in caso di errore sulla CRL
     * @throws CertificateException in caso di errore sul certificato
     * @throws IOException          in caso di errore sullo stream di byte
     */
    private static X509CRL generateCRL(byte[] crlData)
            throws CRLException, CertificateException, IOException {
        X509CRL crl = null;
        try (InputStream is = new ByteArrayInputStream(crlData)) {
            CertificateFactory cf = CertificateFactory.getInstance(X509);
            crl = (X509CRL) cf.generateCRL(is);
        }
        return crl;
    }

    /**
     * Ottieni la CRL utilizzando il provider X.509 BouncyCastle.
     *
     * @param crlData CRL in forma binaria (DER)
     *
     * @return oggetto crl o null
     *
     * @throws CertificateException    in caso di errore sul certificato
     * @throws NoSuchProviderException in caso che il provider BC non sia stato registrato
     * @throws CRLException            in caso di errore sulla CRL
     * @throws IOException             in caso di errore sullo stream di byte
     */
    private static X509CRL generateCRLWithBouncyCastle(byte[] crlData)
            throws CertificateException, NoSuchProviderException, CRLException, IOException {
        X509CRL crl = null;
        try (InputStream is = new ByteArrayInputStream(crlData)) {
            CertificateFactory cf = CertificateFactory.getInstance(X509, BC_PROVIDER);
            crl = (X509CRL) cf.generateCRL(is);
        }
        return crl;
    }

    Vector getDERValue(ASN1Primitive derObj) {

        // new case !
        if (derObj instanceof DLSequence) {
            Vector ret = new Vector();
            DLSequence seq = (DLSequence) derObj;
            Enumeration enumra = seq.getObjects();
            while (enumra.hasMoreElements()) {
                ASN1Primitive nestedObj = (ASN1Primitive) enumra.nextElement();
                Vector appo = getDERValue(nestedObj);
                if (appo != null) {
                    ret.addAll(appo);
                }
            }
            return ret;

        }

        if (derObj instanceof DERSequence) {
            Vector ret = new Vector();
            DERSequence seq = (DERSequence) derObj;
            Enumeration enumra = seq.getObjects();
            while (enumra.hasMoreElements()) {
                ASN1Primitive nestedObj = (ASN1Primitive) enumra.nextElement();
                Vector appo = getDERValue(nestedObj);
                if (appo != null) {
                    ret.addAll(appo);
                }
            }
            return ret;
        }

        if (derObj instanceof DERTaggedObject) {
            DERTaggedObject derTag = (DERTaggedObject) derObj;
            ASN1Primitive object = derTag.getBaseObject().toASN1Primitive();
            if (derTag.isExplicit() || !(object instanceof DEROctetString)) {
                Vector ret = getDERValue(object);
                return ret;
            } else {
                DEROctetString derOct = (DEROctetString) object;
                String val = new String(derOct.getOctets());
                Vector ret = new Vector();
                ret.add(val);
                return ret;
            }
        }

        // new case !
        if (derObj instanceof DLTaggedObject) {
            DLTaggedObject dlTag = (DLTaggedObject) derObj;
            ASN1Primitive object = dlTag.getBaseObject().toASN1Primitive();
            if (dlTag.isExplicit() || !(object instanceof DEROctetString)) {
                Vector ret = getDERValue(object);
                return ret;
            } else {
                DEROctetString derOct = (DEROctetString) object;
                String val = new String(derOct.getOctets());
                Vector ret = new Vector();
                ret.add(val);
                return ret;
            }
        }
        return null;
    }

}
