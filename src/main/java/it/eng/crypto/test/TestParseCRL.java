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

package it.eng.crypto.test;

import it.eng.crypto.CryptoConfiguration;
import it.eng.crypto.CryptoConstants;
import it.eng.crypto.controller.bean.ValidationInfos;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class TestParseCRL {

    private static String filePath = "C:\\Users\\Quaranta_M\\Desktop\\testasc\\CRL_2050";
    private static String urlDistribuzione = "http://onsitecrl.arubapec.trustitalia.it/ArubaPECSpACertificationAuthority/LatestCRL.crl";

    private static X509CRL ricercaCrlByProxyHTTP(String url, CryptoConfiguration configuration)
            throws Exception {
        DefaultHttpClient httpclient = new DefaultHttpClient();
        Credentials credential = new UsernamePasswordCredentials(configuration.getProxyUser(),
                configuration.getProxyPassword());
        AuthScope scope = new AuthScope(configuration.getProxyHost(), configuration.getProxyPort());
        HttpHost proxy = new HttpHost(configuration.getProxyHost(), configuration.getProxyPort());
        httpclient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
        httpclient.getCredentialsProvider().setCredentials(scope, credential);

        HttpPost method = new HttpPost(url);
        HttpResponse httpResponse = httpclient.execute(method);

        if (httpResponse.getStatusLine().getStatusCode() == HttpURLConnection.HTTP_FORBIDDEN) {
            method.abort();
            HttpGet getmethod = new HttpGet(url);
            httpResponse = httpclient.execute(getmethod);
        }
        // java.io.InputStream in = httpResponse.getEntity().getContent();
        return parse(EntityUtils.toByteArray(httpResponse.getEntity()));
    }

    private static X509CRL parse(byte[] crlEnc) throws Exception {
        if (crlEnc == null) {
            return null;
        }
        byte[] crlData;
        try {
            org.bouncycastle.util.encoders.Base64 dec = new org.bouncycastle.util.encoders.Base64();
            crlData = dec.decode(crlEnc);
        } catch (Exception e) {
            crlData = crlEnc;
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        return (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlData));
    }

    protected static void checkCRL(X509CRL crl) {
        Set<X509CRLEntry> entries = (Set<X509CRLEntry>) crl.getRevokedCertificates();
        for (X509CRLEntry crlEntry : entries) {
            System.out.println("revocation date: " + crlEntry.getRevocationDate() + " SN: "
                    + crlEntry.getSerialNumber());
        }
    }

    /**
     * @param args
     */
    public static void main(String[] args) {

        // ApplicationContext context = new ClassPathXmlApplicationContext("ControllerConfig.xml");
        // CryptoConfiguration config = (CryptoConfiguration)
        // context.getBean(CryptoConstants.CRYPTO_CONFIGURATION);
        //
        // try {
        // X509CRL crl = ricercaCrlByProxyHTTP(urlDistribuzione, config);
        // checkCRL(crl);
        // } catch (Exception e1) {
        // // TODO Auto-generated catch block
        // e1.printStackTrace();
        // }
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        File file = new File(filePath);
        try {
            FileInputStream fis = new FileInputStream(file);
            byte[] content = IOUtils.toByteArray(fis);
            X509CRL crl = parse(content);
            checkCRL(crl);
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }
}
