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

import java.io.File;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import it.eng.crypto.controller.bean.DocumentAndTimeStampInfoBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.data.signature.ISignature;
import it.eng.crypto.exception.CryptoSignerException;
import it.eng.crypto.manager.SignatureManager;

public class TestSignatureManager {

    private static final File examplesURL = new File(
	    (new File(TestSignatureManager.class.getResource("../../../../").getFile())).getParent()
		    + "/examples");
    private static File inputFile = null;
    private static File inputFileDetached = null;
    private static final String TSR = "\\P7M\\controfirma\\1SHA1_1controfirma_1controfirma_1controfirma.pdf.p7m.tsr";
    private static final String P7M = "\\P7M\\controfirma\\1SHA1_1controfirma_1controfirma_1controfirma.pdf.p7m";
    private static final String P7M_1 = "\\P7M\\lettera a fornitori ASC.pdf.p7m";
    private static final String TSR_1 = "\\P7M\\lettera a fornitori ASC.pdf.p7m.tsr";
    private static final String P7M_DETACHED_FAKE_FILE = "\\P7M\\detached\\FAKE_CERTIFY_CDS.XML";
    private static final String P7M_DETACHED_FILE = "\\P7M\\detached\\CERTIFY_CDS.XML";
    private static final String P7M_DETACHED_SIGN = "\\P7M\\detached\\CERTIFY_CDS.XML.p7s";
    private static final String P7M_DETACHED_TSR = "\\P7M\\detached\\CERTIFY_CDS.XML.p7s.tsr";
    private static final String P7M_VERTICAL = "\\P7M\\verticale\\PRM.pdf.p7m.p7m.";
    private static final String P7M_VERTICAL_TSR = "\\P7M\\verticale\\PRM.pdf.p7m.p7m.tsr";
    private static final String CADES_XML_VERTICAL = "\\CADES\\verticale\\XAdEST-ATTACH-ES-SIG-FORGED-NG-V131.xml.p7m";
    private static final String CADES_XML_VERTICAL_FAKE_TSR = "\\CADES\\verticale\\XAdEST-ATTACH-ES-SIG-FORGED-NG-V131.xml.p7m.tsr";
    private static final String XML = "\\XaDES\\Long-term storage Plug Test\\10005\\XAdEST-ATTACH-SIGTS-REVOKED-NG-V131.xml";
    private static final String M7M = "\\M7M\\1Firma_CAScaduta.pdf.m7m";
    private static final String M7M_DETACHED_FILE = "\\M7M\\detached\\firma_controfirma_fakeTsr.doc";
    private static final String M7M_DETACHED_SIGN = "\\M7M\\detached\\firma_controfirma_fakeTsr.doc.m7m";
    private static final String M7M_VERTICAL = "\\M7M\\verticale\\PRM.pdf.p7m.m7m";
    private static final String CADES = "\\CaDES\\controfirma\\firma_controfirma_2controfirme.der";
    private static final String CADES_DETACHED_FILE = "\\CaDES\\detached\\test2.doc";
    private static final String CADES_DETACHED_SIGN = "\\CaDES\\detached\\test2.doc.p7m";
    private static final String CADES_VERTICAL = "\\CaDES\\verticale\\1SHA1_1controfirma_1controfirma_1controfirma.pdf.p7m.p7m";
    private static final String PDF = "\\PDF\\DigitalSignaturesInPDF_SCADUTO.pdf";
    private static final String PDF_2 = "\\PDF\\PDF_signer_timestamping.pdf";
    private static final String PDF_3 = "\\PDF\\PDFFirmato.pdf";
    private static final String PDF_4 = "\\PDF\\SampleSignedPDFDocument.pdf";
    private static final String TSR_CHAIN1_CONTENTFILE = "\\Tsr\\ricevuta.pdf";
    private static final String TSR_CHAIN1_TSR_1 = "\\Tsr\\ricevuta.pdf.tsr";
    private static final String TSR_CHAIN1_TSR_2 = "\\Tsr\\ricevuta.pdf.tsr.tsr";
    private static final String TSR_CHAIN2_CONTENTFILE = "\\Tsr\\extensions\\rfc3161.txt.valido.der.p7m";
    private static final String TSR_CHAIN2_TSR_1 = "\\Tsr\\extensions\\rfc3161.txt.valido.der.p7m.tsr";
    private static final String TSR_CHAIN2_TSR_2 = "\\Tsr\\extensions\\rfc3161.txt.valido.der.p7m.tsr.tsr";
    private static final String TSR_CHAIN2_TSR_3 = "\\Tsr\\extensions\\rfc3161.txt.valido.der.p7m.tsr.tsr.tsr";
    private static final String TSR_CHAIN3_CONTENTFILE = "\\Tsr\\extensions\\rfc3161.txt.valido.der.p7m";
    private static final String TSR_CHAIN3_TSR_1 = "\\Tsr\\extensions\\rfc3161.txt.valido.der.p7m.tsr";
    private static final String TSR_CHAIN3_TSR_2 = "\\P7M\\controfirma\\1SHA1_1controfirma_1controfirma_1controfirma.pdf.p7m.tsr";
    private static final String TSR_CHAIN3_TSR_3 = "\\Tsr\\extensions\\rfc3161.txt.valido.der.p7m.tsr.tsr";
    private static final String TSR_CHAIN4_CONTENTFILE = "\\Tsr\\extensions\\CERTIFY_CDS.XML";
    private static final String TSR_CHAIN4_SIGNATUREFILE = "\\Tsr\\extensions\\CERTIFY_CDS.XML.p7s";
    private static final String TSR_CHAIN4_TSR_1 = "\\Tsr\\extensions\\CERTIFY_CDS.XML.p7s.tsr";
    private static final String TSR_CHAIN4_TSR_2 = "\\Tsr\\extensions\\CERTIFY_CDS.XML.p7s.tsr.tsr";
    private static final String TSR_CHAIN4_TSR_3 = "\\Tsr\\extensions\\CERTIFY_CDS.XML.p7s.tsr.tsr.tsr";
    private static final String TSR_CHAIN5_CONTENTFILE = "\\Tsr\\extensions\\firma_controfirma.doc";
    private static final String TSR_CHAIN5_SIGNATUREFILE = "\\Tsr\\extensions\\firma_controfirma.doc.m7m";
    private static final String TSR_CHAIN5_TSR_1 = "\\Tsr\\extensions\\firma_controfirma.doc.m7m.tsr";
    private static final String TSR_CHAIN5_TSR_2 = "\\Tsr\\extensions\\firma_controfirma.doc.m7m.tsr.tsr";
    private static final String TSR_CHAIN6_CONTENTFILE = "\\Tsr\\extensions\\PRM.pdf.p7m.m7m";
    private static final String TSR_CHAIN6_TSR_1 = "\\Tsr\\extensions\\PRM.pdf.p7m.m7m.tsr";
    private static final String TSR_SHA256_FILE = "\\Tsr\\XAdES_enveloped_256.xml";
    private static final String TSR_SHA256_TSR = "\\Tsr\\XAdES_enveloped_256.xml.tsr";
    private static final File p7mFile = new File(examplesURL + P7M);
    private static final File p7mDetachedFile = new File(examplesURL + P7M_DETACHED_FILE);
    private static final File p7mDetachedSign = new File(examplesURL + P7M_DETACHED_SIGN);
    private static final File p7mDetachedTime = new File(examplesURL + P7M_DETACHED_TSR);
    private static final File p7mVerticalFile = new File(examplesURL + P7M_VERTICAL);
    private static final File p7mTsrVerticalFile = new File(examplesURL + P7M_VERTICAL_TSR);
    private static final File cadesXmlVerticalFile = new File(examplesURL + CADES_XML_VERTICAL);
    private static final File cadesXmlVerticalFakeTsrFile = new File(
	    examplesURL + CADES_XML_VERTICAL_FAKE_TSR);
    private static final File p7mFile_1 = new File(examplesURL + P7M_1);
    private static final File tsrFile_1 = new File(examplesURL + TSR_1);
    private static final File tsrFile = new File(examplesURL + TSR);
    private static final File xmlFile = new File(examplesURL + XML);
    private static final File m7mFile = new File(examplesURL + M7M);
    private static final File m7mFakeDetachedFile = new File(examplesURL + P7M_DETACHED_FILE);
    private static final File m7mDetachedFile = new File(examplesURL + M7M_DETACHED_FILE);
    private static final File m7mDetachedSign = new File(examplesURL + M7M_DETACHED_SIGN);
    private static final File m7mVerticalFile = new File(examplesURL + M7M_VERTICAL);
    private static final File cadesFile = new File(examplesURL + CADES);
    private static final File cadesDetachedFile = new File(examplesURL + CADES_DETACHED_FILE);
    private static final File cadesDetachedSign = new File(examplesURL + CADES_DETACHED_SIGN);
    private static final File cadesVerticalFile = new File(examplesURL + CADES_VERTICAL);
    private static final File pdfFile = new File(examplesURL + PDF);
    private static final File pdfFile_2 = new File(examplesURL + PDF_2);
    private static final File pdfFile_3 = new File(examplesURL + PDF_3);
    private static final File pdfFile_4 = new File(examplesURL + PDF_4);
    private static final File tsrChain1File = new File(examplesURL + TSR_CHAIN1_CONTENTFILE);
    private static final File tsrChain1_tsr1 = new File(examplesURL + TSR_CHAIN1_TSR_1);
    private static final File tsrChain1_tsr2 = new File(examplesURL + TSR_CHAIN1_TSR_2);
    private static final File tsrChain2File = new File(examplesURL + TSR_CHAIN2_CONTENTFILE);
    private static final File tsrChain2_tsr1 = new File(examplesURL + TSR_CHAIN2_TSR_1);
    private static final File tsrChain2_tsr2 = new File(examplesURL + TSR_CHAIN2_TSR_2);
    private static final File tsrChain2_tsr3 = new File(examplesURL + TSR_CHAIN2_TSR_3);
    private static final File tsrChain3File = new File(examplesURL + TSR_CHAIN3_CONTENTFILE);
    private static final File tsrChain3_tsr1 = new File(examplesURL + TSR_CHAIN3_TSR_1);
    private static final File tsrChain3_tsr2 = new File(examplesURL + TSR_CHAIN3_TSR_2);
    private static final File tsrChain3_tsr3 = new File(examplesURL + TSR_CHAIN3_TSR_3);
    private static final File tsrChain4ContentFile = new File(examplesURL + TSR_CHAIN4_CONTENTFILE);
    private static final File tsrChain4SignatureFile = new File(
	    examplesURL + TSR_CHAIN4_SIGNATUREFILE);
    private static final File tsrChain4_tsr1 = new File(examplesURL + TSR_CHAIN4_TSR_1);
    private static final File tsrChain4_tsr2 = new File(examplesURL + TSR_CHAIN4_TSR_2);
    private static final File tsrChain4_tsr3 = new File(examplesURL + TSR_CHAIN4_TSR_3);
    private static final File tsrChain5ContentFile = new File(examplesURL + TSR_CHAIN5_CONTENTFILE);
    private static final File tsrChain5SignatureFile = new File(
	    examplesURL + TSR_CHAIN5_SIGNATUREFILE);
    private static final File tsrChain5_tsr1 = new File(examplesURL + TSR_CHAIN5_TSR_1);
    private static final File tsrChain5_tsr2 = new File(examplesURL + TSR_CHAIN5_TSR_2);
    private static final File tsrChain6ContentFile = new File(examplesURL + TSR_CHAIN6_CONTENTFILE);
    private static final File tsrChain6_tsr1 = new File(examplesURL + TSR_CHAIN6_TSR_1);
    private static final File tsrSHA256File = new File(examplesURL + TSR_SHA256_FILE);
    private static final File tsrSHA256_tsr = new File(examplesURL + TSR_SHA256_TSR);
    /*
     * Contesto di configurazione
     */
    ApplicationContext context;

    public static void main(String[] args) {
	Date referenceDate = null;
	if (args.length != 0) {
	    inputFile = new File(args[0]);
	    if (args.length == 2) {
		String input1 = args[1];
		inputFileDetached = new File(args[1]);
		if (!inputFileDetached.exists()) {
		    inputFileDetached = null;
		    DateFormat formatter = new SimpleDateFormat("dd/MM/yy");
		    try {
			referenceDate = (Date) formatter.parse(input1);
		    } catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		    }
		}
	    }
	}
	TestSignatureManager test = new TestSignatureManager();
	try {
	    test.execute(referenceDate);
	} catch (CryptoSignerException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}
    }

    public void execute(Date referenceDate) throws CryptoSignerException {
	context = new ClassPathXmlApplicationContext("ControllerConfig.xml");

	SignatureManager manager = (SignatureManager) context.getBean("SignatureManager");
	OutputSignerBean outputSignerBean = null;

	/*
	 * Tipi di test
	 */
	Map<FileList, OutputSignerBean> results = new HashMap<FileList, OutputSignerBean>();

	if (inputFile != null) {
	    if (inputFileDetached == null) {
		results.put(new FileList(new File[] {
			inputFile }), manager.executeEmbedded(inputFile, referenceDate));
	    } else {
		results.put(new FileList(new File[] {
			inputFile, inputFileDetached }),
			manager.executeDetached(inputFile, inputFileDetached, referenceDate));
	    }
	} else {
	    // // P7M Embedded
	    // results.put(new FileList(new File[]{p7mFile}), manager.executeEmbedded(p7mFile));
	    // // M7M Embedded
	    // results.put(new FileList(new File[]{m7mFile}), manager.executeEmbedded(m7mFile));
	    // // CADES Embedded
	    // results.put(new FileList(new File[]{cadesFile}), manager.executeEmbedded(cadesFile));
	    // // XADES
	    // results.put(new FileList(new File[]{xmlFile}), manager.executeEmbedded(xmlFile));
	    // // P7M + TSR
	    // results.put(new FileList(new File[]{p7mFile, tsrFile}),
	    // manager.executeEmbedded(p7mFile, tsrFile));
	    // // P7M Detached
	    // results.put(new FileList(new File[]{p7mDetachedFile, p7mDetachedSign}),
	    // manager.executeDetached(p7mDetachedFile, p7mDetachedSign));
	    // // CADES Detached
	    // results.put(new FileList(new File[]{cadesDetachedFile, cadesDetachedSign}),
	    // manager.executeDetached(cadesDetachedFile, cadesDetachedSign));
	    // // M7M Detached
	    // results.put(new FileList(new File[]{m7mFakeDetachedFile, m7mDetachedSign}),
	    // manager.executeDetached(m7mFakeDetachedFile, m7mDetachedSign));
	    // P7M Detached + TSR
	    results.put(new FileList(new File[] {
		    p7mDetachedFile, p7mDetachedSign, p7mDetachedTime }),
		    manager.executeDetached(p7mDetachedFile, p7mDetachedSign, p7mDetachedTime));
	    // // P7M Verticale + TSR
	    // results.put(new FileList(new File[]{p7mVerticalFile, p7mTsrVerticalFile}),
	    // manager.executeEmbedded(p7mVerticalFile, p7mTsrVerticalFile));
	    // // CADES Verticale
	    // results.put(new FileList(new File[]{cadesVerticalFile}),
	    // manager.executeEmbedded(cadesVerticalFile));
	    // // M7M Verticale
	    // results.put(new FileList(new File[]{m7mVerticalFile}),
	    // manager.executeEmbedded(m7mVerticalFile));
	    // // CADES Verticale su XML + TSR fake
	    // results.put(new FileList(new File[]{cadesXmlVerticalFile,
	    // cadesXmlVerticalFakeTsrFile}),
	    // manager.executeEmbedded(cadesXmlVerticalFile, cadesXmlVerticalFakeTsrFile));
	    // // PDF
	    // results.put(new FileList(new File[]{pdfFile}), manager.executeEmbedded(pdfFile));
	    // results.put(new FileList(new File[]{pdfFile_2}), manager.executeEmbedded(pdfFile_2));
	    // results.put(new FileList(new File[]{pdfFile_3}), manager.executeEmbedded(pdfFile_3));
	    // results.put(new FileList(new File[]{pdfFile_4}), manager.executeEmbedded(pdfFile_4));
	    //
	    // // TSR EXTENSION CHAIN 1
	    // results.put(new FileList(new File[]{tsrChain1File, tsrChain1_tsr1, tsrChain1_tsr2}),
	    // manager.executeEmbedded(tsrChain1File, tsrChain1_tsr1, new File[]{tsrChain1_tsr2}));
	    //
	    // // TSR EXTENSION CHAIN 2
	    // results.put(new FileList(new File[]{tsrChain2File, tsrChain2_tsr1, tsrChain2_tsr2,
	    // tsrChain2_tsr3}),
	    // manager.executeEmbedded(tsrChain2File, tsrChain2_tsr1, new File[]{tsrChain2_tsr2,
	    // tsrChain2_tsr3}));
	    //
	    // // TSR EXTENSION CHAIN 3
	    // results.put(new FileList(new File[]{tsrChain3File, tsrChain3_tsr1, tsrChain3_tsr2,
	    // tsrChain3_tsr3}),
	    // manager.executeEmbedded(tsrChain3File, tsrChain3_tsr1, new File[]{tsrChain3_tsr2,
	    // tsrChain3_tsr3}));
	    //
	    // // TSR EXTENSION CHAIN 4
	    // results.put(new FileList(new File[]{tsrChain4ContentFile, tsrChain4SignatureFile,
	    // tsrChain4_tsr1,
	    // tsrChain4_tsr2, tsrChain4_tsr3}), manager.executeDetached(tsrChain4ContentFile,
	    // tsrChain4SignatureFile,
	    // tsrChain4_tsr1, new File[]{tsrChain4_tsr2, tsrChain4_tsr3}));
	    //
	    // // TSR EXTENSION CHAIN 5
	    // results.put(new FileList(new File[]{tsrChain5ContentFile, tsrChain5SignatureFile,
	    // tsrChain5_tsr1,
	    // tsrChain5_tsr2 }), manager.executeDetached(tsrChain5ContentFile,
	    // tsrChain5SignatureFile, new
	    // File[]{tsrChain5_tsr1, tsrChain5_tsr2}));
	    //
	    // // TSR EXTENSION CHAIN 6
	    // results.put(new FileList(new File[]{tsrChain6ContentFile, tsrChain6_tsr1}),
	    // manager.executeEmbedded(tsrChain6ContentFile, new File[]{tsrChain6_tsr1}));
	    //
	    // // TSR SHA-256
	    // results.put(new FileList(new File[]{tsrSHA256File, tsrSHA256_tsr}),
	    // manager.executeEmbedded(tsrSHA256File, tsrSHA256_tsr));
	    //
	    //
	    // // Test SignatureManagerConfig
	    // SignatureManagerConfig signatureManagerConfig = new SignatureManagerConfig();
	    // signatureManagerConfig.setContentType(ContentType.DETACHED_CONTENT);
	    // signatureManagerConfig.setContentFile(tsrChain4ContentFile);
	    // signatureManagerConfig.setSignatureFile(tsrChain4SignatureFile);
	    // signatureManagerConfig.setTimeStampEmbedded(false);
	    // signatureManagerConfig.setTimeStampFile(tsrChain4_tsr1);
	    // signatureManagerConfig.setTimeStampExtensions(new File[]{tsrChain4_tsr2,
	    // tsrChain4_tsr3});
	    // results.put(new FileList(new File[]{tsrChain4ContentFile, tsrChain4SignatureFile,
	    // tsrChain4_tsr1,
	    // tsrChain4_tsr2, tsrChain4_tsr3, new File("")}),
	    // manager.execute(signatureManagerConfig));

	}

	Set<FileList> files = results.keySet();
	for (FileList file : files) {
	    System.out.println(
		    "\n############################################################\n Analisi di: \n\t"
			    + file.toString());
	    outputSignerBean = results.get(file);
	    if (outputSignerBean == null) {
		System.out.println("L'analisi non ha prodotto risultato");
	    } else {
		analyzeOutput(outputSignerBean);
	    }
	}

    }

    protected void analyzeOutput(OutputSignerBean outputSignerBean) {
	OutputSignerBean currentOutput = outputSignerBean;
	int step = 1;
	while (currentOutput != null) {
	    System.out.println("************************************************************");
	    System.out.println(" [ BUSTA " + step + "]");
	    analyzeOutputStep(currentOutput);
	    currentOutput = currentOutput.getChild();
	    step++;
	}
    }

    protected void analyzeOutputStep(OutputSignerBean currentOutput) {

	/*
	 * Proprietà in output
	 */
	List<DocumentAndTimeStampInfoBean> timeStampInfos = (List<DocumentAndTimeStampInfoBean>) currentOutput
		.getProperty(OutputSignerBean.TIME_STAMP_INFO_PROPERTY);
	String outputFormat = (String) currentOutput
		.getProperty(OutputSignerBean.ENVELOPE_FORMAT_PROPERTY);
	List<ISignature> signatures = (List<ISignature>) currentOutput
		.getProperty(OutputSignerBean.SIGNATURE_PROPERTY);
	Map<ISignature, ValidationInfos> signatureValidations = (Map<ISignature, ValidationInfos>) currentOutput
		.getProperty(OutputSignerBean.SIGNATURE_VALIDATION_PROPERTY);
	Map<ISignature, ValidationInfos> formatValidity = (Map<ISignature, ValidationInfos>) currentOutput
		.getProperty(OutputSignerBean.FORMAT_VALIDITY_PROPERTY);
	Map<ISignature, ValidationInfos> certificateExpirations = (Map<ISignature, ValidationInfos>) currentOutput
		.getProperty(OutputSignerBean.CERTIFICATE_EXPIRATION_PROPERTY);
	Map<ISignature, ValidationInfos> crlValidation = (Map<ISignature, ValidationInfos>) currentOutput
		.getProperty(OutputSignerBean.CRL_VALIDATION_PROPERTY);
	Map<ISignature, ValidationInfos> unqualifiedSignatures = (Map<ISignature, ValidationInfos>) currentOutput
		.getProperty(OutputSignerBean.CERTIFICATE_UNQUALIFIED_PROPERTY);
	Map<ISignature, ValidationInfos> certificateAssociation = (Map<ISignature, ValidationInfos>) currentOutput
		.getProperty(OutputSignerBean.CERTIFICATE_VALIDATION_PROPERTY);
	String masterSignerException = (String) currentOutput
		.getProperty(OutputSignerBean.MASTER_SIGNER_EXCEPTION_PROPERTY);

	if (timeStampInfos == null || timeStampInfos.size() == 0) {
	    System.out.println("Timestamp non trovato");
	} else {
	    for (DocumentAndTimeStampInfoBean timeStampInfo : timeStampInfos) {
		System.out.println("Marca temporale: \n" + timeStampInfo);
	    }
	}

	int nFirme = signatures == null ? 0 : signatures.size();
	System.out.println("\nNumero di firme: " + nFirme + "\n");

	int i = 1;
	if (signatures != null) {
	    System.out.println("Formato della busta: " + outputFormat);
	    if (masterSignerException != null && !"".equals(masterSignerException.trim())) {
		System.out.println(
			"Errore durante l'esecuzione dei controlli relativo al controller: "
				+ masterSignerException);
	    } else {
		System.out.println("Esecuzione dei controlli conclusa correttamente");
	    }
	    System.out.println("Controllo di validità temporale del formato: " + formatValidity);
	    for (ISignature signature : signatures) {

		System.out.println("\n[Firma " + i + "]");

		ValidationInfos signatureValidationInfos = signatureValidations.get(signature);
		System.out.println("\t Validazione della firma: " + signatureValidationInfos);

		if (certificateExpirations != null) {
		    ValidationInfos certificateExpirationInfos = certificateExpirations
			    .get(signature);
		    System.out
			    .println("\t Scadenza del certificato: " + certificateExpirationInfos);
		}

		if (crlValidation != null) {
		    ValidationInfos crlValidationInfos = crlValidation.get(signature);
		    System.out.println("\t Revoca del certificato: " + crlValidationInfos);
		}

		if (certificateAssociation != null) {
		    ValidationInfos certificateAssociationInfos = certificateAssociation
			    .get(signature);
		    System.out.println("\t Associazione tra certificato di firma e issuer: "
			    + certificateAssociationInfos);
		}

		if (unqualifiedSignatures != null) {
		    ValidationInfos certificateReliabilityInfo = unqualifiedSignatures
			    .get(signature);
		    if (certificateReliabilityInfo != null) {
			System.out.println("\t Certificato di firma NON ACCREDITATO: "
				+ certificateReliabilityInfo);
		    } else {
			System.out.println("\t Certificato di firma ACCREDITATO");
		    }
		}

		List<ISignature> counterSignatures = signature.getCounterSignatures();
		if (counterSignatures != null && counterSignatures.size() != 0) {
		    String padding = "\t\t";
		    String signatureIndex = "[" + i + "]";
		    printCounterSignatures(padding, signatureIndex, counterSignatures,
			    signatureValidations, certificateExpirations, crlValidation,
			    unqualifiedSignatures);
		}
		i++;
	    }
	}
    }

    protected void printCounterSignatures(String padding, String signatureIndex,
	    List<ISignature> countersignatures,
	    Map<ISignature, ValidationInfos> signatureValidations,
	    Map<ISignature, ValidationInfos> certificateExpirations,
	    Map<ISignature, ValidationInfos> crlValidation,
	    Map<ISignature, ValidationInfos> unqualifiedSignatures) {
	System.out.println("\t La firma " + signatureIndex + ". contiene "
		+ countersignatures.size() + " controfirme");
	int i = 1;
	for (ISignature countersignature : countersignatures) {
	    printCounterSignatureCheck(padding, countersignature, signatureValidations,
		    certificateExpirations, crlValidation, unqualifiedSignatures);
	    List<ISignature> counterCountersignatures = countersignature.getCounterSignatures();
	    if (counterCountersignatures != null && counterCountersignatures.size() != 0) {
		String newPadding = padding + "\t";
		printCounterSignatures(newPadding, signatureIndex + "[" + i + "]",
			counterCountersignatures, signatureValidations, certificateExpirations,
			crlValidation, unqualifiedSignatures);
	    }
	    i++;
	}
    }

    protected void printCounterSignatureCheck(String padding, ISignature countersignature,
	    Map<ISignature, ValidationInfos> signatureValidations,
	    Map<ISignature, ValidationInfos> certificateExpirations,
	    Map<ISignature, ValidationInfos> crlValidation,
	    Map<ISignature, ValidationInfos> unqualifiedSignatures) {
	ValidationInfos countersignatureValidationInfos = signatureValidations
		.get(countersignature);
	System.out.println(
		padding + " Validazione della controfirma: " + countersignatureValidationInfos);

	if (certificateExpirations != null) {
	    ValidationInfos countersignatureCertificateExpirationInfos = certificateExpirations
		    .get(countersignature);
	    System.out.println(padding + " Scadenza del certificato della controfirma: "
		    + countersignatureCertificateExpirationInfos);
	}

	if (crlValidation != null) {
	    ValidationInfos countersignatureCrlValidationInfos = crlValidation
		    .get(countersignature);
	    System.out.println(padding + " Revoca del certificato della controfirma: "
		    + countersignatureCrlValidationInfos);
	}

	if (unqualifiedSignatures != null) {
	    ValidationInfos certificateReliabilityInfo = unqualifiedSignatures
		    .get(countersignature);
	    if (certificateReliabilityInfo != null) {
		System.out.println(padding + " Certificato della controfirma NON ACCREDITATO: "
			+ certificateReliabilityInfo);
	    } else {
		System.out.println(padding + " Certificato della controfirma ACCREDITATO");
	    }
	}
    }

    class FileList extends ArrayList<File> {

	public FileList(File[] files) {
	    super();
	    for (File file : files) {
		super.add(file);
	    }
	}

	public String toString() {
	    StringBuffer stringBuffer = new StringBuffer();
	    for (ListIterator<File> iterator = this.listIterator(); iterator.hasNext();) {
		stringBuffer.append(iterator.next().getName());
		if (iterator.hasNext()) {
		    stringBuffer.append(", ");
		}
	    }
	    return stringBuffer.toString();
	}
    }
}
