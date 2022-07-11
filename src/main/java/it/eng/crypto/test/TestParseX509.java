/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.eng.crypto.test;

import it.eng.crypto.data.SignerUtil;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.io.IOUtils;

/**
 *
 * @author Quaranta_M
 */
public class TestParseX509 {

    private static String filePath = "/home/marco/Scrivania/tsa.cer";

    public static void main(String[] args) {

        // ApplicationContext context = new ClassPathXmlApplicationContext("ControllerConfig.xml");
        // CryptoConfiguration config = (CryptoConfiguration) context.getBean(CryptoConstants.CRYPTO_CONFIGURATION);
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
            // create the certificate factory
            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
            // read the certificate
            X509Certificate x509Cert = (X509Certificate) fact.generateCertificate(new ByteArrayInputStream(content));
            // X509Certificate ca = new X509Certificate
            System.out.println(x509Cert.getIssuerX500Principal().getName());
            System.out.println("AUTH KEY: " + SignerUtil.getAuthorityKeyId(x509Cert));
            System.out.println("SUBJ KEY: " + SignerUtil.getSubjectKeyId(x509Cert));
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
