package it.eng.crypto.test;

import it.eng.crypto.CryptoConfiguration;
import it.eng.crypto.CryptoConstants;

import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.impl.client.DefaultHttpClient;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.w3c.dom.Document;

import be.fedict.eid.tsl.TrustService;
import be.fedict.eid.tsl.TrustServiceList;
import be.fedict.eid.tsl.TrustServiceListFactory;
import be.fedict.eid.tsl.TrustServiceProvider;

public class TestTSL {

    public static void main(String[] args) {
        // List<X509Certificate> qualifiedCertificates = new ArrayList<X509Certificate>();
        Map<Principal, X509Certificate> qualifiedCertificates = new HashMap<Principal, X509Certificate>();
        try {
            // Modifica per adeguamento EIDAS vedi
            // http://www.agid.gov.it/agenda-digitale/infrastrutture-architetture/firme-elettroniche/certificati
            // String urlString = "https://applicazioni.cnipa.gov.it/TSL/IT_TSL_signed.xml";
            String urlString = "https://eidas.agid.gov.it/TL/TSL-IT.xml";
            // HttpsURL url = new HttpsURL(urlString);
            HttpGet method = new HttpGet(urlString);

            ApplicationContext context = new ClassPathXmlApplicationContext("ControllerConfig.xml");
            CryptoConfiguration config = (CryptoConfiguration) context.getBean(CryptoConstants.CRYPTO_CONFIGURATION);

            DefaultHttpClient httpclient = new DefaultHttpClient();
            if (config.isProxy()) {
                Credentials credential = config.isNTLSAuth()
                        ? new NTCredentials(config.getProxyUser(), config.getProxyPassword(), config.getUserHost(),
                                config.getUserDomain())
                        : new UsernamePasswordCredentials(config.getProxyUser(), config.getProxyPassword());
                HttpHost proxy = new HttpHost(config.getProxyHost(), config.getProxyPort());
                httpclient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
                httpclient.getCredentialsProvider().setCredentials(new AuthScope(proxy.getHostName(), proxy.getPort()),
                        credential);

            }
            HttpResponse response = httpclient.execute(method);

            java.io.InputStream is = response.getEntity().getContent();

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder docBuilder = factory.newDocumentBuilder();

            Document doc = docBuilder.parse(is);

            is.close();

            TrustServiceList trustServiceList = TrustServiceListFactory.newInstance(doc);
            List<TrustServiceProvider> trustServiceProviders = trustServiceList.getTrustServiceProviders();

            for (TrustServiceProvider trustServiceProvider : trustServiceProviders) {
                List<TrustService> trustServices = trustServiceProvider.getTrustServices();
                for (TrustService trustService : trustServices) {
                    X509Certificate certificate = trustService.getServiceDigitalIdentity();
                    // qualifiedCertificates.add(certificate);
                    qualifiedCertificates.put(certificate.getSubjectX500Principal(), certificate);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        Set<Principal> principals = qualifiedCertificates.keySet();
        for (Principal principal : principals) {
            System.out.println(principal);
        }

    }

    public static String print(InputStream in) throws IOException {
        StringBuffer out = new StringBuffer();
        byte[] b = new byte[4096];
        for (int n; (n = in.read(b)) != -1;) {
            out.append(new String(b, 0, n));
        }
        return out.toString();
    }
}
