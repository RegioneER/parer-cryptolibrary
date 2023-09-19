/*
 * Engineering Ingegneria Informatica S.p.A.
 *
 * Copyright (C) 2023 Regione Emilia-Romagna
 * <p/>
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Affero General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 * <p/>
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

// package it.eng.crypto.ca.impl;
//
// import it.eng.crypto.CryptoConfiguration;
// import it.eng.crypto.CryptoSingleton;
// import it.eng.crypto.FactorySigner;
// import it.eng.crypto.bean.ConfigBean;
// import it.eng.crypto.ca.CAObserver;
// import it.eng.crypto.ca.ICertificateAuthority;
// import it.eng.crypto.controller.bean.ValidationInfos;
// import it.eng.crypto.data.SignerUtil;
// import it.eng.crypto.exception.CryptoSignerException;
// import it.eng.crypto.exception.CryptoStorageException;
//
// import java.io.File;
// import java.io.InputStream;
// import java.net.HttpURLConnection;
// import java.security.cert.CertificateFactory;
// import java.security.cert.X509CRL;
// import java.security.cert.X509Certificate;
// import java.util.Enumeration;
// import java.util.HashMap;
// import java.util.List;
// import java.util.Map;
// import java.util.Observable;
//
// import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
// import org.apache.commons.compress.archivers.zip.ZipFile;
//// import org.apache.commons.httpclient.HttpClient;
//// import org.apache.commons.httpclient.methods.PostMethod;
// import org.apache.http.HttpHost;
// import org.apache.http.HttpResponse;
// import org.apache.http.auth.AuthScope;
// import org.apache.http.auth.NTCredentials;
// import org.apache.http.client.HttpClient;
// import org.apache.http.client.methods.HttpGet;
// import org.apache.http.client.methods.HttpPost;
// import org.apache.http.conn.params.ConnRoutePNames;
// import org.apache.http.impl.client.DefaultHttpClient;
// import org.apache.http.util.EntityUtils;
// import org.apache.commons.io.FileUtils;
// import org.apache.commons.io.IOUtils;
// import org.apache.log4j.Logger;
// import org.bouncycastle.jce.provider.BouncyCastleProvider;
//
/// **
// * Implementazione di default di una {@link ICertificateAuthority}
// * @author Michele Rigo
// *
// */
// public class DefaultCertificateAuthority extends Observable implements ICertificateAuthority {
//
// Logger log = Logger.getLogger(DefaultCertificateAuthority.class);
//
// public DefaultCertificateAuthority(){
// //Registro l'observer
// CAObserver observer = new CAObserver();
// this.addObserver(observer);
// }
//
// public void updateCertificate() throws CryptoSignerException {
// try{
// log.info("updateCertificate START");
//
// CryptoConfiguration config = CryptoSingleton.getInstance().getConfiguration();
//
// //Recupero i certificati valida da CNIPA
// String url = "http://www.cnipa.gov.it/site/_files/lista%20dei%20certificati.html";
//
// //HTTPCLIENT 3.1
//// PostMethod method = new PostMethod(url);
//// method.getHostConfiguration().setProxy(config.getProxyHost(), config.getProxyPort());
//// method.addRequestHeader("Proxy-Authorization", config.getProxyAuth());
//// HttpClient http_client = new HttpClient();
//// http_client.executeMethod(method);
//
// //HTTPCLIENT 4
// DefaultHttpClient httpclient = new DefaultHttpClient();
// HttpHost proxy = new HttpHost(config.getProxyHost(), config.getProxyPort());
// httpclient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
// httpclient.getCredentialsProvider().setCredentials(new AuthScope(proxy.getHostName(),proxy.getPort()), new
// NTCredentials(config.getProxyUser(),config.getProxyPassword(),"ibc3617","RERSDM"));
// HttpPost postMethod = new HttpPost(url);
// HttpResponse httpResponse = httpclient.execute(postMethod);
//
//
//
//
// //Parserizzo la pagina html per recuperare l'indirizzo valido per il recupero del file
// // List<String> linee = IOUtils.readLines(method.getResponseBodyAsStream());
// InputStream is = httpResponse.getEntity().getContent();
// List<String> linee = IOUtils.readLines(is);
// String tmps = "";
// for(int i=0;i<linee.size();i++){
// if(linee.get(i).startsWith("<a")){
// tmps = linee.get(i);
// }
// }
//
// // method.releaseConnection();
// is.close();
//
// javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
// factory.setNamespaceAware(false);
// factory.setIgnoringElementContentWhitespace(true);
// factory.setValidating(false);
// javax.xml.parsers.DocumentBuilder builder = null;
// builder = factory.newDocumentBuilder();
// org.w3c.dom.Document document = builder.parse(IOUtils.toInputStream(tmps));
//
// if(document.getFirstChild()!=null){
// //Recupero l'href del link
// String urlFile = document.getFirstChild().getAttributes().getNamedItem("href").getNodeValue();
//
// //Recupero il file
//// PostMethod method2 = new PostMethod(urlFile);
//// method2.getHostConfiguration().setProxy(config.getProxyHost(), config.getProxyPort());
//// method2.addRequestHeader("Proxy-Authorization", config.getProxyAuth());
//// HttpClient http_client2 = new HttpClient();
//// http_client2.executeMethod(method2);
//
// postMethod = new HttpPost(urlFile);
// httpResponse = httpclient.execute(postMethod);
//
//
//
// //File firmato contenente i certificati validi
// // byte[] zipfile = httpResponse.getResponseBody();
// byte[] zipfile = EntityUtils.toByteArray(httpResponse.getEntity());
// //method2.releaseConnection();
//
// //Creo un file temporaneo
// File p7m = File.createTempFile("CA", ".P7M");
//
// FileUtils.writeByteArrayToFile(p7m, zipfile);
//
// //Map<String,ValidationInfos> complianceChecks = null;
// //prendo il file zippato
// InputStream stream = SignerUtil.newInstance().getSignerManager(p7m).getUnsignedContent();
//
// //Scansiono il file zippato
// File tmp = File.createTempFile("TMP", ".zip");
// FileUtils.writeByteArrayToFile(tmp, IOUtils.toByteArray(stream));
//
// ZipFile zip = new ZipFile(tmp);
// Enumeration<?> entries = zip.getEntries();
// CertificateFactory factorys = CertificateFactory.getInstance("X509", BouncyCastleProvider.PROVIDER_NAME);
// while(entries.hasMoreElements()){
// ZipArchiveEntry entry = (ZipArchiveEntry)entries.nextElement();
// if(!entry.isDirectory()){
//// String name = entry.getName();
// try{
// X509Certificate certificato = (X509Certificate)factorys.generateCertificate(zip.getInputStream(entry));
// //Controllo che il certificato sia valido
// if(certificato!=null){
// this.setChanged();
// this.notifyObservers(certificato);
// }
// }catch(Exception e){
// log.warn("Warning parsing certificate",e);
// }
// }
// }
// tmp.delete();
// //Registro i task
// FactorySigner.registerTask();
//
// //Ristarto tutti i task
// FactorySigner.startTask();
// }
// log.info("updateCertificate END");
// }catch(Exception e){
// log.error("updateCertificate",e);
// throw new RuntimeException(e);
// }
// }
//
// public void revokeControll() throws CryptoSignerException {
// try{
// log.info("revokeControll START");
// //Recupero le configurazioni attive
// List<X509Certificate> activeCertificate = FactorySigner.getInstanceCAStorage().retriveActiveCA();
// if(activeCertificate!=null){
// for(int i=0;i<activeCertificate.size();i++){
// //Recupero l'url della CRL dal DB
// ConfigBean bean =
// FactorySigner.getInstanceConfigStorage().retriveConfig(activeCertificate.get(i).getIssuerX500Principal().getName());
// try{
// X509CRL crl = SignerUtil.newInstance().getCrlByURL(bean.getCrlURL());
// boolean revoke = crl.isRevoked(activeCertificate.get(i));
// if(revoke){
// //Certificato revocato salvo l'ultima CRL appena scaricata e stoppo il task di aggiornamento CRL
// FactorySigner.getInstanceCRLStorage().insertCRL(crl);
// //Revoco il certificato
// FactorySigner.getInstanceCAStorage().revokeCA(activeCertificate.get(i));
// //Stoppo il task di aggiornamento della CRL
// FactorySigner.unregisterTask(activeCertificate.get(i).getSubjectX500Principal().getName());
// }
// }catch(CryptoSignerException e){
// log.warn("Warning recupero CRL",e);
// }
// }
// }
// log.info("revokeControll END");
// }catch(CryptoStorageException e){
// log.error("revokeControll",e);
// throw new CryptoSignerException(e);
// }
// }
// }
