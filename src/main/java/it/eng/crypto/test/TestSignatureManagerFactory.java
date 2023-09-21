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

// package it.eng.crypto.test;
//
// import java.io.File;
//
// import it.eng.crypto.controller.bean.OutputSignerBean;
// import it.eng.crypto.exception.CryptoSignerException;
// import it.eng.crypto.manager.SignatureManager;
// import it.eng.crypto.manager.factory.SignatureManagerFactory;
// import it.eng.crypto.utils.OutputAnalyzer;
//
// public class TestSignatureManagerFactory {
//
// public static void main(String[] args) {
//
// File contentFile =new File("C:\\Documents and
// Settings\\Administrator\\Desktop\\tar21054443\\ed89b352-de93-4f68-858d-25394aa5a940");
// File signatureFile =new File("C:\\Documents and
// Settings\\Administrator\\Desktop\\tar21054443\\3b6839e7-3993-484e-9b25-262cbc95d8cd");
//
// SignatureManagerFactory factory = SignatureManagerFactory.newInstance("c:/tmp/CAStorage", "c:/tmp/CAStorage",
// "c:/tmp/CAStorage");
// SignatureManager signatureManager = factory.newSignatureManager();
// try {
// OutputSignerBean output = signatureManager.executeEmbedded(contentFile, signatureFile);
// OutputAnalyzer analyzer = new OutputAnalyzer(output);
// analyzer.printReport();
// } catch (CryptoSignerException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// }
// }
//
// }
