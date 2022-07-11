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
