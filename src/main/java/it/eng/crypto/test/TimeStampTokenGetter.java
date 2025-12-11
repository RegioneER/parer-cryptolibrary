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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

public class TimeStampTokenGetter {

    HttpPost method;
    byte content[];

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        TimeStampTokenGetter tmp = new TimeStampTokenGetter(new HttpPost("http://www.google.it"),
                IOUtils.toByteArray(new FileInputStream("c:\\odg.pdf")));
        TimeStampToken token = tmp.getTimeStampToken();

        System.out.println(token);

    }

    public TimeStampTokenGetter(HttpPost method, byte[] content) {
        this.method = method;
        this.content = content;
    }

    public TimeStampToken getTimeStampToken() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1", "BC");
            byte fingerprints[] = md.digest(content);

            TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
            reqGen.setCertReq(true);

            TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, fingerprints);
            System.out.println(request.getMessageImprintDigest().length);

            byte[] valor1 = request.getMessageImprintDigest();
            System.out.println(valor1.length);

            for (int i = 0; i < valor1.length; i++) {

                System.out.print(valor1[i] + ":");

            }
            System.out.println();

            byte enc_req[] = request.getEncoded();

            ByteArrayInputStream bais = new ByteArrayInputStream(enc_req);

            // method.getHostConfiguration().setProxy("proxy.eng.it", 3128);
            // method.setRequestBody(bais);
            // method.setRequestContentLength(enc_req.length);

            // method.addRequestHeader("Proxy-Authorization", auth);

            HttpPost method = new HttpPost("http://www.tecnes.com/javasign/timestamp");
            // method.setRequestHeader("Content-type", "application/timestamp-data");
            // method.setRequestHeader("Content-Transfer-Encoding", "binary");

            HttpEntity ent = new InputStreamEntity(bais, bais.available());
            method.setEntity(ent);

            DefaultHttpClient httpclient = new DefaultHttpClient();
            HttpResponse hr = httpclient.execute(method);
            java.io.InputStream in = hr.getEntity().getContent();

            // System.out.println(IOUtils.toString(in));

            TimeStampResponse resp = new TimeStampResponse(in);
            resp.validate(request);
            System.out.println("TimestampResponse validated");
            TimeStampToken tsToken = resp.getTimeStampToken();
            SignerId signer_id = tsToken.getSID();
            BigInteger cert_serial_number = signer_id.getSerialNumber();

            // Refactored certificate extraction for Bouncy Castle 1.50
            Store certStore = tsToken.getCertificates();
            Collection<X509CertificateHolder> certHolders = certStore.getMatches(null);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = null;
            for (X509CertificateHolder holder : certHolders) {
                X509Certificate cert = (X509Certificate) certFactory
                        .generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
                System.out.println("Certificate serial " + cert.getSerialNumber());
                System.out.println("Certificate subject dn " + cert.getSubjectX500Principal());
                if (cert_serial_number != null) {
                    if (cert.getSerialNumber().equals(cert_serial_number)) {
                        System.out.println(
                                "using certificate with serial: " + cert.getSerialNumber());
                        certificate = cert;
                    }
                } else if (certificate == null) {
                    certificate = cert;
                }
            }

            // tsToken.validate(certificate, "BC");
            System.out.println("QAUIIII:" + tsToken);
            return tsToken;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
