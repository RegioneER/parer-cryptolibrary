/*
 * Engineering Ingegneria Informatica S.p.A.
 *
 * Copyright (C) 2023 Regione Emilia-Romagna <p/> This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version. <p/> This program is distributed in the hope that it
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Affero General Public License for more details. <p/> You should have received a copy
 * of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

// package it.eng.crypto.ca.impl;
//
// import it.eng.crypto.CryptoConfiguration;
// import it.eng.crypto.CryptoSingleton;
// import it.eng.crypto.exception.CryptoSignerException;
//
// import java.security.cert.X509Certificate;
// import java.util.List;
//
// import javax.xml.parsers.DocumentBuilder;
// import javax.xml.parsers.DocumentBuilderFactory;
//
// import org.apache.http.HttpHost;
// import org.apache.http.HttpResponse;
// import org.apache.http.auth.AuthScope;
// import org.apache.http.auth.Credentials;
// import org.apache.http.auth.NTCredentials;
// import org.apache.http.auth.UsernamePasswordCredentials;
// import org.apache.http.client.methods.HttpGet;
// import org.apache.http.conn.params.ConnRoutePNames;
// import org.apache.http.impl.client.DefaultHttpClient;
// import org.w3c.dom.Document;
//
// import be.fedict.eid.tsl.TrustService;
// import be.fedict.eid.tsl.TrustServiceList;
// import be.fedict.eid.tsl.TrustServiceListFactory;
// import be.fedict.eid.tsl.TrustServiceProvider;
//
/// **
// * Estensione di una {@link DefaultCertificateAuthority}: effettua lo
// * scaricamento e il parsing della lista dei certificati attendibili a partire
// * da una Trust Service Status List
// *
// * @author Administrator
// *
// */
// public class TSLCertificateAuthority extends DefaultCertificateAuthority {
//
// @Override
// public void updateCertificate() throws CryptoSignerException {
//
// try {
// CryptoConfiguration cryptoConfiguration = CryptoSingleton.getInstance().getConfiguration();
// String urlString = cryptoConfiguration.getQualifiedCertificatesURL();
// HttpGet method = new HttpGet(urlString);
//
// DefaultHttpClient httpclient = new DefaultHttpClient();
// if (cryptoConfiguration.isProxy()) {
// Credentials credential = cryptoConfiguration.isNTLSAuth()
// ? new NTCredentials(cryptoConfiguration.getProxyUser(), cryptoConfiguration.getProxyPassword(),
// cryptoConfiguration.getUserHost(), cryptoConfiguration.getUserDomain())
// : new UsernamePasswordCredentials(cryptoConfiguration.getProxyUser(), cryptoConfiguration.getProxyPassword());
// HttpHost proxy = new HttpHost(cryptoConfiguration.getProxyHost(), cryptoConfiguration.getProxyPort());
// httpclient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
// httpclient.getCredentialsProvider().setCredentials(new AuthScope(proxy.getHostName(), proxy.getPort()), credential);
// }
// HttpResponse httpResponse = httpclient.execute(method);
//
// java.io.InputStream is = httpResponse.getEntity().getContent();
//
// DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
// factory.setNamespaceAware(true);
// DocumentBuilder docBuilder = factory.newDocumentBuilder();
//
// Document doc = docBuilder.parse(is);
//
// is.close();
//
// TrustServiceList trustServiceList = TrustServiceListFactory.newInstance(doc);
// List<TrustServiceProvider> trustServiceProviders = trustServiceList.getTrustServiceProviders();
//
// for (TrustServiceProvider trustServiceProvider : trustServiceProviders) {
// List<TrustService> trustServices = trustServiceProvider.getTrustServices();
// for (TrustService trustService : trustServices) {
// X509Certificate certificate = trustService.getServiceDigitalIdentity();
//
// // Notifico il nuovo certificato agli observer
// this.setChanged();
// this.notifyObservers(certificate);
// }
// }
// } catch (Exception e) {
// throw new CryptoSignerException("Errore nel recupero dei certificati accreditati: ", e);
// }
// }
// }
