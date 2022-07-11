package it.eng.crypto.data;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
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
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
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
     * Recupera le CRL tramite il protocollo HTTP/HTTPS
     *
     * @param url
     *            ottieni le CRL dall'url (se raggiungibile)
     * 
     * @return CRL o null
     * 
     * @throws IOException
     * @throws CryptoSignerException
     * @throws Exception
     */
    X509CRL ricercaCrlByProxyHTTP(String url, CryptoConfiguration configuration)
            throws IOException, CryptoSignerException, Exception {

        // set the connection timeout value to 20 seconds (20000 milliseconds)
        final int timeout = 20000;
        final HttpParams httpParams = new BasicHttpParams();
        HttpConnectionParams.setConnectionTimeout(httpParams, timeout);
        HttpConnectionParams.setSoTimeout(httpParams, timeout);
        // e-trustcom.intesa ha un certificato non firmato da un CA root

        DefaultHttpClient httpclient = new DefaultHttpClient(httpParams);
        if (url.contains("e-trustcom.intesa.it")) {
            httpclient = CRLUtil.wrapClient(httpclient);
        }

        if (configuration.isProxy()) {
            Credentials credential = configuration.isNTLSAuth()
                    ? new NTCredentials(configuration.getProxyUser(), configuration.getProxyPassword(),
                            configuration.getUserHost(), configuration.getUserDomain())
                    : new UsernamePasswordCredentials(configuration.getProxyUser(), configuration.getProxyPassword());
            HttpHost proxy = new HttpHost(configuration.getProxyHost(), configuration.getProxyPort());
            httpclient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
            httpclient.getCredentialsProvider().setCredentials(new AuthScope(proxy.getHostName(), proxy.getPort()),
                    credential);
        }

        HttpPost method = new HttpPost(url);
        HttpResponse httpResponse = null;
        HttpEntity he = null;
        try {
            httpResponse = httpclient.execute(method);
            if (httpResponse.getStatusLine().getStatusCode() != HttpURLConnection.HTTP_OK) {
                he = httpResponse.getEntity();
                EntityUtils.consume(he);
                method.abort();
                HttpGet getMethod = new HttpGet(url);
                httpResponse = httpclient.execute(getMethod);
            }
            he = httpResponse.getEntity();
            if (httpResponse.getStatusLine().getStatusCode() == HttpURLConnection.HTTP_OK) {
                byte[] content = EntityUtils.toByteArray(he);

                if (content.length != 0) {
                    return parse(content);
                } else {
                    method.abort();
                    HttpGet getMethod = new HttpGet(url);
                    httpResponse = httpclient.execute(getMethod);
                    he = httpResponse.getEntity();
                    if (httpResponse.getStatusLine().getStatusCode() == HttpURLConnection.HTTP_OK) {
                        content = EntityUtils.toByteArray(he);
                        return parse(content);
                    } else {
                        throw new CryptoSignerException(
                                "Il server ha ritornato il codice: " + httpResponse.getStatusLine().getStatusCode());
                    }
                }
            } else {
                throw new CryptoSignerException(
                        "Il server ha ritornato il codice: " + httpResponse.getStatusLine().getStatusCode());
            }
        } catch (IOException e) {
            throw new CryptoSignerException("La connessione è stata interrotta per un errore", e);
        } finally {
            EntityUtils.consume(he);
        }

    }

    /**
     * Recupera le CRL tramite il protocollo LDAP
     *
     * @param url
     * 
     * @return
     * 
     * @throws Exception
     */
    X509CRL searchCrlByLDAP(String url) throws Exception {
        final String timeout = "20000";
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
                if (a.getID() != null && a.getID().toLowerCase().indexOf("certificaterevocationlist") != -1) {
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
    // ******************************************************************************************************************************
    // Metodi di utilità
    // ******************************************************************************************************************************

    /**
     * Parsa l'array di byte in ingresso per recuperare la CRL
     * 
     * @param crlEnc
     *            byte array della crl così come fornito dall'url
     * 
     * @return crl o null
     */
    public static X509CRL parse(byte[] crlEnc) throws Exception {
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
            LOG.debug("CRL non parsabile con provider Java, provo con BouncyCastle Errore: {}", e.getMessage());
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
     * In alcuni casi il base64 decoder di BC non è in grado di interpretare il base64 del certificato perché
     * presentato su più righe. In questo caso elimino i caratteri di fine linea (e il boundary del ascii armor) ed
     * utilizzo il decoder standard di java.
     * 
     * @param crlEnc
     *            CRL in formato base64
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
                LOG.debug("CRL non parsabile con provider Java, provo con BouncyCastle Errore: {}", e.getMessage());
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
     * @param crlData
     *            CRL in forma binaria (DER)
     * 
     * @return oggetto crl o null
     * 
     * @throws CRLException
     *             in caso di errore sulla CRL
     * @throws CertificateException
     *             in caso di errore sul certificato
     * @throws IOException
     *             in caso di errore sullo stream di byte
     */
    private static X509CRL generateCRL(byte[] crlData) throws CRLException, CertificateException, IOException {
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
     * @param crlData
     *            CRL in forma binaria (DER)
     * 
     * @return oggetto crl o null
     * 
     * @throws CertificateException
     *             in caso di errore sul certificato
     * @throws NoSuchProviderException
     *             in caso che il provider BC non sia stato registrato
     * @throws CRLException
     *             in caso di errore sulla CRL
     * @throws IOException
     *             in caso di errore sullo stream di byte
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

    Vector getDERValue(DERObject derObj) {
        if (derObj instanceof DERSequence) {
            Vector ret = new Vector();
            DERSequence seq = (DERSequence) derObj;
            Enumeration enumra = seq.getObjects();
            while (enumra.hasMoreElements()) {
                DERObject nestedObj = (DERObject) enumra.nextElement();
                Vector appo = getDERValue(nestedObj);
                if (appo != null) {
                    ret.addAll(appo);
                }
            }
            return ret;
        }

        if (derObj instanceof DERTaggedObject) {
            DERTaggedObject derTag = (DERTaggedObject) derObj;
            DERObject object = derTag.getObject();
            if (derTag.isExplicit() && !derTag.isEmpty() || !(object instanceof DEROctetString)) {
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

    public static DefaultHttpClient wrapClient(HttpClient base) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            X509TrustManager tm = new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
                }

                public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            };
            ctx.init(null, new X509TrustManager[] { tm }, null);
            SSLSocketFactory ssf = new SSLSocketFactory(ctx, SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
            ClientConnectionManager ccm = base.getConnectionManager();
            SchemeRegistry sr = ccm.getSchemeRegistry();
            sr.register(new Scheme("https", 443, ssf));
            return new DefaultHttpClient(ccm, base.getParams());
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }
}
