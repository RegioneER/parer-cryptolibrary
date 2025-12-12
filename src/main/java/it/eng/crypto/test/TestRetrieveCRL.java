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

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Enumeration;
import java.util.Vector;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchResult;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.impl.client.DefaultHttpClient;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64Encoder;

public class TestRetrieveCRL {

    private static final SimpleDateFormat format = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

    /**
     * @param args
     */
    public static void main(String[] args) throws Exception {

        try {

            Security.addProvider(new BouncyCastleProvider());

            CryptoConfiguration config = new CryptoConfiguration();

            config.setProxyHost("proxy.eng.it");
            config.setProxyPort(3128);
            config.setProxyPassword("fv54kagz");
            config.setProxyUser("mirigo");

            String url = "http://www.google.it/";

            // Recupero i certificati valida da CNIPA
            // String url = "http://www.cnipa.gov.it/site/_files/lista%20dei%20certificati.html";
            HttpPost method = new HttpPost(url);
            Credentials credential = config.isNTLSAuth()
                    ? new NTCredentials(config.getProxyUser(), config.getProxyPassword(),
                            config.getUserHost(), config.getUserDomain())
                    : new UsernamePasswordCredentials(config.getProxyUser(),
                            config.getProxyPassword());
            HttpHost proxy = new HttpHost(config.getProxyHost(), config.getProxyPort());
            DefaultHttpClient hc = new DefaultHttpClient();
            hc.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
            hc.getCredentialsProvider().setCredentials(
                    new AuthScope(proxy.getHostName(), proxy.getPort()), credential);

            HttpResponse hr = hc.execute(method);

            System.out.println(IOUtils.toString(hr.getEntity().getContent()));

            // //Parserizzo la pagina html per recuperare l'indirizzo valido per il recupero del
            // file
            // javax.xml.parsers.DocumentBuilderFactory factory =
            // javax.xml.parsers.DocumentBuilderFactory.newInstance();
            // factory.setNamespaceAware(false);
            // factory.setIgnoringElementContentWhitespace(true);
            // factory.setValidating(false);
            //
            //
            // javax.xml.parsers.DocumentBuilder builder = null;
            // builder = factory.newDocumentBuilder();
            //
            // System.out.println(method.getResponseBodyAsString());
            //
            // List<String> linee = IOUtils.readLines(method.getResponseBodyAsStream());
            // String tmps = "";
            // for(int i=0;i<linee.size();i++){
            // if(linee.get(i).startsWith("<a")){
            // tmps = linee.get(i);
            // }
            // }
            //
            //
            // ByteArrayOutputStream out = new ByteArrayOutputStream();
            //
            // IOUtils.writeLines(linee, "", out);
            //
            // org.w3c.dom.Document document = builder.parse(IOUtils.toInputStream(tmps));
            // NodeList links = document.getElementsByTagName("a");
            //
            // System.out.println(links.getLength());
            //
            // if(links!=null && links.getLength()>=1){
            // //Recupero l'href del link
            // String urlFile = links.item(0).getAttributes().getNamedItem("href").getNodeValue();
            //
            // //Recupero il file
            // PostMethod method2 = new PostMethod(urlFile);
            // method2.getHostConfiguration().setProxy(config.getProxyHost(),
            // config.getProxyPort());
            // method2.addRequestHeader("Proxy-Authorization", config.getProxyAuth());
            // HttpClient http_client2 = new HttpClient();
            // http_client2.executeMethod(method2);
            //
            // //File firmato contenente i certificati validi
            // byte[] zipfile = method2.getResponseBody();
            //
            // //prendo il file zippato
            // DocumentBean documentBean =
            // SignerUtil.newInstance().getSignerManager(zipfile).extract(zipfile);
            // System.out.println(documentBean.getSigners().get(0).getSubject().getName());
            //
            // //Scansiono il file zippato
            // File tmp = File.createTempFile("TMP", ".zip");
            //
            //
            // FileUtils.writeByteArrayToFile(tmp, documentBean.getOutput());
            // CertificateFactory factorys = CertificateFactory.getInstance("X509",
            // BouncyCastleProvider.PROVIDER_NAME);
            // ZipFile zip = new ZipFile(tmp);
            // Enumeration<?> entries = zip.getEntries();
            // while(entries.hasMoreElements()){
            // ZipArchiveEntry entry = (ZipArchiveEntry)entries.nextElement();
            // if(!entry.isDirectory()){
            // String name = entry.getName();
            // try{
            // X509Certificate certif =
            // (X509Certificate)factorys.generateCertificate(zip.getInputStream(entry));
            // System.out.println(certif.getType());
            // }catch(Exception e){
            // System.out.println("ERRORE FILE:"+name);
            // }
            // }
            // }
            //
            // tmp.delete();
            // }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Security.addProvider(new BouncyCastleProvider());
        //
        // X509CRL crl;

        // crl.isRevoked(cert)

        // CNIPA URL
        // String url = "http://www.cnipa.gov.it/site/_files/lista%20dei%20certificati.html";
        // String url = "http://www.cnipa.gov.it/site/_files/LISTACER_20100408.zip.p7m";
        // PostMethod method = new PostMethod(url);
        // method.getHostConfiguration().setProxy("proxy.eng.it", 3128);
        // String auth = "Basic " + new String(new
        // org.apache.commons.codec.binary.Base64().encode("mirigo:fv54kagz".getBytes()));
        // method.addRequestHeader("Proxy-Authorization", auth);
        // HttpClient http_client = new HttpClient();
        // http_client.executeMethod(method);
        // //java.io.InputStream in = ;
        //
        // System.out.println(method.getResponseBodyAsString());

        // LDAPHelper helper = new LDAPHelper("", "", "ldapca.spcoop.gov.it", "Servizi di Sicurezza
        // e Certificazione",
        // "CNIPA CA3");
        // System.out.println(helper.userVerify());
        // helper.retriveParameter("certificaterevocationlist");
        //
        // NumberFormat format = new DecimalFormat("#,#0");
        // Number number = format.parse("120.45");
        //
        // Number number3 = NumberFormat.getNumberInstance(Locale.ITALIAN).parse("-1.234,56");
        // System.out.println(number3.doubleValue());
        //
        // String ldapUrl = "ldap://ldapca.spcoop.gov.it";
        // X509CRL ret = null;
        // DirContext ctx = new InitialDirContext();
        //
        // System.out.println(ctx.list(ldapUrl));
        //
        // NamingEnumeration ne = ctx.search(ldapUrl,"CNIPA CA3",null);
        // if (ne.hasMore()) {
        // ctx.close();
        // javax.naming.directory.Attributes attribs = ((SearchResult) ne.next()).getAttributes();
        // Attribute a = null;
        // for (NamingEnumeration ae = attribs.getAll(); ae.hasMore(); ) {
        // a = (Attribute) ae.next();
        // if (a.getID() != null && a.getID().toLowerCase().indexOf("certificaterevocationlist") !=
        // -1) {
        // System.out.println(((byte[])a.get(0)).length);
        //
        // //ret = parse((byte[]) a.get(0));
        // break;
        // }
        // }
        // }else{
        // ctx.close();
        // }

        // ICryptoSigner signer = FactorySigner.newInstance();
        // DocumentBean doc = signer.extract(IOUtils.toByteArray(new
        // FileInputStream("F:\\GESTIONALE\\workspace\\cryptoSigner\\example\\PRM.pdf.p7m")));
        //
        // Vector vect =
        // getCrlDistributionPoint((X509Certificate)doc.getLista().get(0).getCertificate());
        // System.out.println(vect);
        //
        // String user = "mirigo";
        // String password = "fv54kagz";
        // String proxyHost = "proxy.eng.it";
        // String proxyPort = "3128";
        // String auth = "";
        // if (user != null && password != null) {
        // String authString = user + ":" + password;
        // auth = "Basic " + new String(new
        // org.apache.commons.codec.binary.Base64().encode(authString.getBytes()));
        // }
        // System.getProperties().put("proxySet", "true");
        // System.getProperties().put("proxyHost", proxyHost);
        // System.getProperties().put("proxyPort", proxyPort);
        // System.setProperty("https.proxyHost", proxyHost);
        // System.setProperty("https.proxyPort", proxyPort);
        //
        // String url = vect.get(0).toString();
        //
        // MyTest test = new MyTest();
        // X509CRL crl = test.ricercaCrlByLDAP(url);
        //
        // System.out.println(crl.getThisUpdate());
        // System.out.println(crl.getNextUpdate());
        //
        //
        // crl.getIssuerX500Principal().getName();

        // PostMethod method = new PostMethod(url);
        // String url="http://tsp.iaik.tugraz.at/tsp/TspRequest";
        // method.getHostConfiguration().setProxy("proxy.eng.it", 3128);
        // method.addRequestHeader("Proxy-Authorization", auth);
        //
        // System.out.println(method.getAuthenticationRealm());
        //
        // HttpClient http_client = new HttpClient();
        // http_client.executeMethod(method);
        // java.io.InputStream in = method.getResponseBodyAsStream();

        // System.out.println(in);

        // File src = new File("F:\\GESTIONALE\\workspace\\cryptoSigner\\example\\PRM.pdf.p7m");
        // File dest = new
        // File("F:\\GESTIONALE\\workspace\\cryptoSigner\\example\\PRM.pdf.p7m.tsr");
        //
        // TimeStampTokenGetter get = new TimeStampTokenGetter(new PostMethod(url),
        // IOUtils.toByteArray(new
        // FileInputStream(src)));
        // TimeStampToken token = get.getTimeStampToken(auth);
        // System.out.println(token);
        // System.out.println(format.format(token.getTimeStampInfo().getGenTime()));
        //
        // System.out.println(new String(token.getTimeStampInfo().getMessageImprintAlgOID()));
        //
        // byte[] valor1 = token.getTimeStampInfo().getMessageImprintDigest();
        // System.out.println(valor1.length);
        //
        // for(int i=0;i<valor1.length;i++){
        //
        // System.out.print(valor1[i]+":");
        //
        // }
        // System.out.println();
        //
        // System.out.println(token.getTimeStampInfo().getMessageImprintDigest());
        //
        //
        //
        //
        // FileUtils.writeByteArrayToFile(dest, token.getEncoded());

    }

    public static Vector getCrlDistributionPoint(X509Certificate certificate)
            throws CertificateParsingException {
        try {
            // ---- alternative code ----------
            byte[] val1 = certificate.getExtensionValue("2.5.29.31");
            ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(val1));
            ASN1Primitive derObj = oAsnInStream.readObject();
            DEROctetString dos = (DEROctetString) derObj;
            byte[] val2 = dos.getOctets();
            ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(val2));
            ASN1Primitive derObj2 = oAsnInStream2.readObject();
            Vector urls = getDERValue(derObj2);
            return urls;
        } catch (Exception e) {
            e.printStackTrace();
            throw new CertificateParsingException(e.toString());
        }
    }

    private static Vector getDERValue(ASN1Primitive derObj) {
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
            if (derTag.isExplicit()) {
                ASN1Primitive nestedObj = derTag.toASN1Primitive();
                Vector ret = getDERValue(nestedObj);
                return ret;
            } else {
                DEROctetString derOct = (DEROctetString) derTag.toASN1Primitive();
                String val = new String(derOct.getOctets());
                Vector ret = new Vector();
                ret.add(val);
                return ret;
            }
        }
        return null;
    }

    private X509CRL ricercaCrlByLDAP(String dp) {

        String ldapUrl = dp;
        try {
            // ldapUrl = dp.toExternalForm();

            if (ldapUrl.toLowerCase().indexOf("?certificaterevocationlist") < 0) {
                ldapUrl = ldapUrl + "?certificaterevocationlist";
                // dp = new URL(ldapUrl);

            }

            // Set up environment for creating initial context
            /*
             * Hashtable env = new Hashtable(11); env.put(Context.INITIAL_CONTEXT_FACTORY,
             * "com.sun.jndi.ldap.LdapCtxFactory"); // env.put(Context.PROVIDER_URL,
             * "ldap://localhost:389/o=JNDITutorial"); env.put(Context.PROVIDER_URL, ldapUrl);
             *
             * // Specify timeout to be 5 seconds env.put("com.sun.jndi.ldap.connect.timeout",
             * "15000");
             *
             * // Create initial context DirContext ctx = new InitialDirContext(env);
             */
            DirContext ctx = new InitialDirContext();

            // FIXME why was this doesn't run?
            // impostazione un timeout...
            /*
             * int timeout = 5000; //5 s SearchControls ctls = new SearchControls();
             * ctls.setSearchScope(SearchControls.SUBTREE_SCOPE); ctls.setTimeLimit(timeout); //
             *
             * NamingEnumeration ne = ctx.search(ldapUrl, "", ctls);
             */
            NamingEnumeration ne = ctx.search(ldapUrl, "", null);
            if (!ne.hasMore()) {

                return null;
            }
            ctx.close();

            javax.naming.directory.Attributes attribs = ((SearchResult) ne.next()).getAttributes();
            Attribute a = null;

            for (NamingEnumeration ae = attribs.getAll(); ae.hasMore();) {
                a = (Attribute) ae.next();

                if (a.getID() != null
                        && a.getID().toLowerCase().indexOf("certificaterevocationlist") != -1) {
                    // CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    // return ((X509CRL)cf.generateCRL(new ByteArrayInputStream((byte[])
                    // crlVector.get(0))));
                    return parse((byte[]) a.get(0));
                }
            }

            return null;
        } // catch (TimeLimitExceededException e) {
          // System.out.println("time limit exceeded: "+e);
          // return null;
          // }
        catch (Exception e) {
            // set the error to the CRL control

            return null;
        }
    }

    private X509CRL parse(byte[] crlEnc) throws Exception {
        if (crlEnc == null) {
            return null;
        }

        byte[] crlData;
        try {
            // Quello di SUN non e' sempre affidabile!!!
            // crlData = new sun.misc.BASE64Decoder().decodeBuffer(new String(crlEnc));
            org.bouncycastle.util.encoders.Base64 dec = new org.bouncycastle.util.encoders.Base64();
            crlData = dec.decode(crlEnc);

        } catch (Exception e) {

            crlData = crlEnc;

        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        return (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlData));
    }
    // public void generate(byte[] contentbytes) throws FileNotFoundException, IOException,
    // NoSuchAlgorithmException,
    // NoSuchProviderException
    // {
    // Security.addProvider(new BouncyCastleProvider());
    // MessageDigest md = MessageDigest.getInstance("SHA-1", "BC");
    // byte fingerprint[] = md.digest(contentbytes);
    // System.out.println("Digest : " + fingerprint);
    // TimeStampToken tst = generateTsrData(fingerprint,"");
    // if(tst == null)
    // {
    // System.out.println("NO TST");
    // throw new IOException("Unable to create Detached Timestamp");
    // } else
    // {
    // byte tsrdata[] = tst.getEncoded();
    // System.out.println("Got tsr " + tsrdata.length + " bytes");
    // System.out.println("Now I encode it in base64");
    // FileOutputStream efos = new FileOutputStream("C:/temp/pippo.tsr");
    // Base64Encoder encoder = new Base64Encoder();
    // encoder.encode(tsrdata, 0, tsrContent.length, fos);
    // efos.close();
    // return;
    // }
    // }
    //
    // public TimeStampToken generateTsrData(byte fingerprint[],String url)
    // {
    // TimeStampToken tst = null;
    // TimeStampTokenGetter tstGetter = new TimeStampTokenGetter(new PostMethod(url), fingerprint,
    // BigInteger.valueOf(0L));
    // tst = tstGetter.getTimeStampToken("");
    // return tst;
    // }
}
