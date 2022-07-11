/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.eng.crypto.controller.bean;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

/**
 *
 * @author quaranta_m
 */
public class TrustChainCheck {

    private X509Certificate cerificate;
    private X509CRL crl;
    private boolean isRootCa;

    public X509Certificate getCerificate() {
        return cerificate;
    }

    public void setCerificate(X509Certificate cerificate) {
        this.cerificate = cerificate;
    }

    public X509CRL getCrl() {
        return crl;
    }

    public void setCrl(X509CRL crl) {
        this.crl = crl;
    }

    public boolean isIsRootCa() {
        return isRootCa;
    }

    public void setIsRootCa(boolean isRootCa) {
        this.isRootCa = isRootCa;
    }

}
