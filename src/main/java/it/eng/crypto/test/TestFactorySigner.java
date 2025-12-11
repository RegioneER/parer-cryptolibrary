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

import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.data.PdfSigner;

import java.io.File;
import java.util.Hashtable;
import java.util.Iterator;

import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Arrays;

public class TestFactorySigner {

    public static void main(String[] args) throws Exception {

        // AbstractSigner manager = SignerUtil.newInstance().getSignerManager(new File(""));
        //
        // TimeStampToken token = manager.getTimeStampToken();
        //
        // token.getTimeStampInfo().getMessageImprintAlgOID();
        //
        // byte[] digestFile = manager.getDigestSigner();
        //
        // byte[] digestToken = token.getTimeStampInfo().getMessageImprintDigest();

        PdfSigner signer = new PdfSigner();
        signer.isSignedType(new File("C:\\ODG2_signed.pdf"), new ValidationInfos());
        TimeStampToken token = signer.getTimeStampTokens()[0];

        MessageImprint imprint = token.getTimeStampInfo().toTSTInfo().getMessageImprint();

        byte[] by = imprint.getHashedMessage();
        System.out.println(new String(by));
        System.out.println(new String(token.getTimeStampInfo().getMessageImprintDigest()));

        System.out.println(((AlgorithmIdentifier) imprint.getHashAlgorithm()).getAlgorithm());

        Hashtable table = token.getSignedAttributes().toHashtable();

        // Attribute obj = (Attribute)table.get(PKCSObjectIdentifiers.pkcs_9_at_messageDigest);

        Iterator itera = table.keySet().iterator();

        while (itera.hasNext()) {
            Object key = itera.next();
            Attribute obj = (Attribute) table.get(key);
            System.out.println(obj.getAttrType() + " - " + obj.getAttrValues());
        }

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        reqGen.setCertReq(true);

        // System.out.println(signer.getDigestSigner());

        // TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1,
        // signer.getUnsignedContent());

        // validate(request,token);

    }

    public static void validate(TimeStampRequest request, TimeStampToken token)
            throws TSPException {
        TimeStampToken tok = token;

        if (tok != null) {
            TimeStampTokenInfo tstInfo = tok.getTimeStampInfo();

            if (request.getNonce() != null && !request.getNonce().equals(tstInfo.getNonce())) {
                throw new TSPValidationException("response contains wrong nonce value.");
            }

            // if (this.getStatus() != PKIStatus.GRANTED && this.getStatus() !=
            // PKIStatus.GRANTED_WITH_MODS)
            // {
            // throw new TSPValidationException("time stamp token found in failed request.");
            // }

            System.out.println(request.getMessageImprintDigest());

            System.out.println(new String(request.getMessageImprintDigest()));
            System.out.println(new String(tstInfo.getMessageImprintDigest()));

            if (!Arrays.constantTimeAreEqual(request.getMessageImprintDigest(),
                    tstInfo.getMessageImprintDigest())) {
                throw new TSPValidationException("response for different message imprint digest.");
            }

            if (!tstInfo.getMessageImprintAlgOID().equals(request.getMessageImprintAlgOID())) {
                throw new TSPValidationException(
                        "response for different message imprint algorithm.");
            }

            Attribute scV1 = tok.getSignedAttributes()
                    .get(PKCSObjectIdentifiers.id_aa_signingCertificate);
            Attribute scV2 = tok.getSignedAttributes()
                    .get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);

            if (scV1 == null && scV2 == null) {
                throw new TSPValidationException("no signing certificate attribute present.");
            }

            if (scV1 != null && scV2 != null) {
                throw new TSPValidationException(
                        "conflicting signing certificate attributes present.");
            }

            if (request.getReqPolicy() != null
                    && !request.getReqPolicy().equals(tstInfo.getPolicy())) {
                throw new TSPValidationException("TSA policy wrong for request.");
            }
        }
        // else if (this.getStatus() == PKIStatus.GRANTED || this.getStatus() ==
        // PKIStatus.GRANTED_WITH_MODS)
        // {
        // throw new TSPValidationException("no time stamp token found and one expected.");
        // }
    }
    // public static byte[]getDigestSigner(File file) throws IOException{
    // InputStream stream = FileUtils.openInputStream(file);
    // //Controllo se è un pdf firmato
    // PdfReader reader = new PdfReader(stream);
    // AcroFields acroFields = reader.getAcroFields();
    //
    // try{
    // ArrayList names = acroFields.getSignatureNames();
    // if(names.size()==1){
    // String name = (String)names.get(0);
    //
    // PdfDictionary dic = acroFields.getSignatureDictionary(name);
    //
    // Iterator<PdfName> iteratore = dic.getKeys().iterator();
    //
    // while(iteratore.hasNext()){
    // System.out.println(iteratore.next());
    // }
    //
    // new CMSSignedData();
    //
    //
    //
    //
    //
    // //PdfPKCS7 pk = acroFields.verifySignature(name);
    //
    // }else{
    // //Firma multipla
    // //TODO da gestire
    // }
    // }catch(Exception e){
    //
    // }
    // return null;
    // }
}
