package it.eng.crypto.test;

import java.io.File;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import it.eng.crypto.controller.MasterSignerController;
import it.eng.crypto.controller.bean.InputSignerBean;
import it.eng.crypto.controller.bean.OutputSignerBean;
import it.eng.crypto.controller.bean.ValidationInfos;
import it.eng.crypto.controller.exception.ExceptionController;
import it.eng.crypto.data.AbstractSigner;
import it.eng.crypto.data.CMSSigner;
import it.eng.crypto.data.signature.ISignature;

public class VerificaTest {

    /*
     * @param args
     * 
     * @throws ExceptionController
     */
    public static void main(String[] args) throws ExceptionController {
        Security.addProvider(new BouncyCastleProvider());
        ApplicationContext context = new ClassPathXmlApplicationContext("NewControllerConfig.xml");
        // AbstractSigner as = new XMLSigner();
        AbstractSigner as = new CMSSigner();
        if (as.isSignedType(new File("C:/1289453.merge.doc.p7m"), new ValidationInfos())) {
            as.setFile(new File("C:/1289453.merge.doc.p7m"));
            for (ISignature is : as.getSignatures()) {
                System.out.println(is.getSignerBean().getCertificate().getSubjectX500Principal());
                System.out.println(is.verify().toString());
            }
            MasterSignerController msc = (MasterSignerController) context.getBean("MasterSigner");
            for (ISignature is : as.getSignatures()) {
                System.out.println(is.getSignerBean().getCertificate().getSubjectX500Principal());
                System.out.println(is.verify().toString());
            }
            InputSignerBean signerBean = new InputSignerBean();
            signerBean.setSigner(as);
            OutputSignerBean osb = msc.executeControll(signerBean);
            System.out.println(osb.toString());
        } else {
            System.out.println("File non firmato");
        }

    }
}