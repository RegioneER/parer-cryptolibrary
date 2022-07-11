package it.eng.crypto.controller.impl.signature;

import java.io.File;
import java.io.IOException;

import it.eng.crypto.controller.bean.ContentBean;
import it.eng.crypto.controller.bean.InputSignerBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.data.AbstractSigner;

/**
 * Recupera il contenuto della busta tramite il metodo {@link it.eng.crypto.data.AbstractSigner#getContentAsFile
 * getContentAsFile} del signer ad esso associato.
 * 
 * @author Administrator
 */
public class ContentExtraction extends AbstractSignerController {

    public boolean execute(InputSignerBean input, OutputSignerBean output) throws ExceptionController {
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
