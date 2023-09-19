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

package it.eng.crypto.controller.impl.timestamp;

import it.eng.crypto.controller.bean.DocumentAndTimeStampInfoBean;
import it.eng.crypto.controller.bean.InputTimeStampBean;
import it.eng.crypto.controller.bean.OutputTimeStampBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.data.AbstractSigner;
import it.eng.crypto.data.type.SignerType;
import it.eng.crypto.exception.CryptoSignerException;
import it.eng.crypto.utils.VerificheEnums.EsitoControllo;
import it.eng.crypto.utils.VerificheEnums.TipoControlli;
import java.io.File;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import java.util.Map;
import org.bouncycastle.tsp.GenTimeAccuracy;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

public class TimeStampExtraction extends AbstractTimeStampController {

    @Override
    public boolean execute(InputTimeStampBean input, OutputTimeStampBean output) throws ExceptionController {

        List<DocumentAndTimeStampInfoBean> documentAndTimeStampInfoList = new ArrayList<DocumentAndTimeStampInfoBean>();
        AbstractSigner signer = null;

        TimeStampToken[] timeStampTokens;
        boolean result = true;
        try {
            // Solo marca embedded
            if (input.getTimeStampWithContentFile() != null) {
                signer = signerUtil.getSignerManager(input.getTimeStampWithContentFile());
                timeStampTokens = signer.getTimeStampTokens();
                if (timeStampTokens != null) {

                    for (TimeStampToken timeStampToken : timeStampTokens) {
                        documentAndTimeStampInfoList.add(addDocumentAndTSInfoBeanEmbedded(
                                input.getTimeStampWithContentFile(), timeStampToken, signer));
                    }
                }
            } // marca detached ed eventualmente embedded
            else {

                signer = signerUtil.getSignerManager(input.getTimeStampFile());
                timeStampTokens = signer.getTimeStampTokens();
                if (timeStampTokens != null) {
                    for (TimeStampToken timeStampToken : timeStampTokens) {
                        documentAndTimeStampInfoList
                                .add(addDocumentAndTSInfoBeanDetached(input.getContentFile(), timeStampToken, signer));
                    }
                }
                try {
                    signer = signerUtil.getSignerManager(input.getContentFile());
                    timeStampTokens = signer.getTimeStampTokens();
                    if (timeStampTokens != null) {
                        for (TimeStampToken timeStampToken : timeStampTokens) {
                            documentAndTimeStampInfoList.add(
                                    addDocumentAndTSInfoBeanEmbedded(input.getContentFile(), timeStampToken, signer));
                        }
                    }
                } catch (CryptoSignerException e) {
                    // se il file embedded non è firmato la signerUtil.getSignerManager() lancia un'eccezione che
                    // farebbe perdere anche l'eventuale marca detached.
                    // Per questo motivo devo catchare l'eccezione e non fare nulla
                }
            }
        } catch (CryptoSignerException e) {
            throw new ExceptionController(e, e.getComplianceChecks());

        } catch (CloneNotSupportedException e) {
            e.printStackTrace();
        }

        output.setDocumentAndTimeStampInfos(documentAndTimeStampInfoList);
        output.setSigner(signer);
        return result;
    }

    private void populateCommonAttributes(DocumentAndTimeStampInfoBean documentAndTimeStampInfo) {
        TimeStampToken timeStampToken = documentAndTimeStampInfo.getTimeStampToken();

        /*
         * Tipo di algorimto utilizzato durante la generazione dell'hash del messaggio - è l'algoritmo impiegato per
         * effettuare l'impronta del file marcato
         */
        TimeStampTokenInfo tokenInfo = timeStampToken.getTimeStampInfo();
        documentAndTimeStampInfo.setProperty(DocumentAndTimeStampInfoBean.PROP_HASH_ALGORITHM,
                tokenInfo.getMessageImprintAlgOID());

        /*
         * Riferimento temporale in millisecondi (se disponibili) della marca
         */
        GenTimeAccuracy accuracy = tokenInfo.getGenTimeAccuracy();
        Long millis = accuracy != null ? tokenInfo.getGenTime().getTime() + tokenInfo.getGenTimeAccuracy().getMillis()
                : tokenInfo.getGenTime().getTime();
        documentAndTimeStampInfo.setProperty(DocumentAndTimeStampInfoBean.PROP_MILLISECS, millis.toString());

        /*
         * Data del riferimento temporale
         */
        Date timestampDate = new Date(tokenInfo.getGenTime().getTime());
        documentAndTimeStampInfo.setProperty(DocumentAndTimeStampInfoBean.PROP_DATE, timestampDate);
    }

    private DocumentAndTimeStampInfoBean addDocumentAndTSInfoBeanEmbedded(File inputFile, TimeStampToken timeStampToken,
            AbstractSigner signer) throws CloneNotSupportedException {
        DocumentAndTimeStampInfoBean documentAndTimeStampInfo = new DocumentAndTimeStampInfoBean();
        documentAndTimeStampInfo.setAssociatedFile(inputFile);
        documentAndTimeStampInfo.setTimeStampToken(timeStampToken);

        /*
         * Formato della marca temporale
         */
        documentAndTimeStampInfo.setProperty(DocumentAndTimeStampInfoBean.PROP_TIMESTAMP_FORMAT,
                signer.getTimeStampFormat());

        /*
         * Tipo di marca (EMBEDDED) oppure EMBEDDED M7M (che di fatto è una detached in append su un p7m)
         */
        if (signer.getFormat().equals(SignerType.M7M)) {
            documentAndTimeStampInfo
                    .setTimeStampTokenType(DocumentAndTimeStampInfoBean.TimeStampTokenType.EMBEDDED_M7M);
        } else if (signer.getFormat().equals(SignerType.TSD)) {
            documentAndTimeStampInfo
                    .setTimeStampTokenType(DocumentAndTimeStampInfoBean.TimeStampTokenType.EMBEDDED_TSD);
        } else {
            documentAndTimeStampInfo.setTimeStampTokenType(DocumentAndTimeStampInfoBean.TimeStampTokenType.EMBEDDED);
        }

        /*
         * Verifica che la marca temporale corrisponda al file di appartenenza
         */
        ValidationInfos infos = signer.validateTimeStampTokensEmbedded(timeStampToken);
        if (infos == null) {
            infos = new ValidationInfos();
            infos.addError("Impossibile completare la validazione oppure la marca non è di tipo: "
                    + documentAndTimeStampInfo.getTimeStampTokenType());
            infos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
        }

        /*
         * Genera gli attributi comuni per tutte le marche temporali
         */
        populateCommonAttributes(documentAndTimeStampInfo);
        documentAndTimeStampInfo.setProperty(TipoControlli.CRITTOGRAFICO.name(), infos.clone());
        documentAndTimeStampInfo.setValidationInfos(infos);
        return documentAndTimeStampInfo;

    }

    private DocumentAndTimeStampInfoBean addDocumentAndTSInfoBeanDetached(File inputFile, TimeStampToken timeStampToken,
            AbstractSigner signer) throws CloneNotSupportedException {
        DocumentAndTimeStampInfoBean documentAndTimeStampInfo = new DocumentAndTimeStampInfoBean();

        documentAndTimeStampInfo.setAssociatedFile(inputFile);
        documentAndTimeStampInfo.setTimeStampToken(timeStampToken);

        /*
         * Formato della marca temporale
         */
        documentAndTimeStampInfo.setProperty(DocumentAndTimeStampInfoBean.PROP_TIMESTAMP_FORMAT,
                signer.getTimeStampFormat());

        /*
         * Tipo di marca (DETACHED)
         */
        documentAndTimeStampInfo.setTimeStampTokenType(DocumentAndTimeStampInfoBean.TimeStampTokenType.DETACHED);

        /*
         * Verifica che la marca temporale corrisponda al file di appartenenza
         */
        ValidationInfos infos = signer.validateTimeStampTokensDetached(inputFile);

        if (infos == null) {
            infos = new ValidationInfos();
            infos.addError("Impossibile completare la validazione oppure la marca non è di tipo: "
                    + documentAndTimeStampInfo.getTimeStampTokenType());
            infos.setEsito(EsitoControllo.FORMATO_NON_CONOSCIUTO);
        }
        /*
         * Genera gli attributi comuni per tutte le marche temporali
         */
        populateCommonAttributes(documentAndTimeStampInfo);
        documentAndTimeStampInfo.setProperty(TipoControlli.CRITTOGRAFICO.name(), infos.clone());
        documentAndTimeStampInfo.setValidationInfos(infos);
        return documentAndTimeStampInfo;
    }
}
