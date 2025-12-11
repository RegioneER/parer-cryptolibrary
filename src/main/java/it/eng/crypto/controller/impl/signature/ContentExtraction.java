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

package it.eng.crypto.controller.impl.signature;

import java.io.File;
import java.io.IOException;

import it.eng.crypto.controller.bean.ContentBean;
import it.eng.crypto.controller.bean.InputSignerBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.data.AbstractSigner;

/**
 * Recupera il contenuto della busta tramite il metodo
 * {@link it.eng.crypto.data.AbstractSigner#getContentAsFile getContentAsFile} del signer ad esso
 * associato.
 *
 * @author Administrator
 */
public class ContentExtraction extends AbstractSignerController {

    public boolean execute(InputSignerBean input, OutputSignerBean output)
            throws ExceptionController {
        AbstractSigner signer = input.getSigner();
        File contentFile;
        try {
            contentFile = signer.getContentAsFile();
        } catch (IOException e) {
            throw new ExceptionController(e);
        }
        ContentBean content = new ContentBean();
        content.setPossiblySigned(signer.canContentBeSigned());
        content.setContentFile(contentFile);
        output.setContent(content);
        return true;
    }

}
