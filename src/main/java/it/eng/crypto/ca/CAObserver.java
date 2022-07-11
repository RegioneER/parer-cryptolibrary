package it.eng.crypto.ca;

import it.eng.crypto.FactorySigner;
import it.eng.crypto.bean.ConfigBean;
import it.eng.crypto.data.SignerUtil;
import it.eng.crypto.exception.CryptoSignerException;
import it.eng.crypto.exception.CryptoStorageException;

import java.io.ByteArrayInputStream;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Observable;
import java.util.Observer;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Definisce una classe che assume il ruolo di osservatore rispetto a una {@link it.eng.crypto.ca.ICertificateAuthority
 * Certification Authority}.
 *
 * @author Michele Rigo
 *
 */
public class CAObserver implements Observer {

    Logger log = LoggerFactory.getLogger(CAObserver.class);
    private static final String SINC = "SINC";
    private static SimpleDateFormat format = new SimpleDateFormat("H m d M *");

    /**
     * Metodo richiamato all'inserimento di un nuovo certificato.
     *
     * Alla notifica del cambiamento di stato dell'istanza osservata viene salvato nello storage il certificato
     * indicato. Inoltre viene recuperato il distribution point della CRL e istanziati 3 task che eseguono giornalmente
     * lo scaricamento della crl a partire dal terzo giorno precedente alla data di scadenza. La CRL attuale viene
     * inoltre salvata nello Storage CRL .
     *
     * @param o
     *            istanza della classe osservata ({@link it.eng.crypto.ca.ICertificateAuthority Certification
     *            Authority})
     * @param obj
     *            oggetto della chiamata notify ({@link java.security.cert.X509Certificate})
     */
    public void update(Observable o, Object obj) {
        synchronized (SINC) {
            log.info("update START");
            try {
                // Salvo il certificato sullo storage
                FactorySigner.getInstanceCAStorage().insertCA((X509Certificate) obj);

                try {
                    X509Certificate cert = (X509Certificate) obj;
                    ASN1InputStream aIn = new ASN1InputStream(cert.getEncoded());
                    ASN1Sequence seq = (ASN1Sequence) aIn.readObject();

                    X509CertificateStructure obj2 = new X509CertificateStructure(seq);
                    TBSCertificateStructure tbsCert = obj2.getTBSCertificate();

                    X509Extensions ext = tbsCert.getExtensions();

                    Enumeration enumera = ext.oids();
                    while (enumera.hasMoreElements()) {
                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) enumera.nextElement();
                        org.bouncycastle.asn1.x509.X509Extension extVal = ext.getExtension(oid);
                        ASN1OctetString oct = extVal.getValue();
                        ASN1InputStream extIn = new ASN1InputStream(new ByteArrayInputStream(oct.getOctets()));
                        if (oid.equals(X509Extension.cRLDistributionPoints)) {
                            log.debug("SubjectDN:" + ((X509Certificate) obj).getIssuerX500Principal().getName());
                            CRLDistPoint p = CRLDistPoint.getInstance(extIn.readObject());
                            DistributionPoint[] points = p.getDistributionPoints();
                            for (int i = 0; i != points.length; i++) {
                                String ret = StringUtils.remove(points[i].getDistributionPoint().getName().toString(),
                                        "GeneralNames:");
                                log.debug("Distriution Point:" + ret);
                                if (StringUtils.trim(ret).startsWith("6:")) {
                                    // Salvo l'url di recupero CRL
                                    ret = StringUtils.remove(StringUtils.trim(ret), "6:");

                                    // Creo una nuova configurazione
                                    ConfigBean config = new ConfigBean();
                                    config.setCrlURL(ret);

                                    Date date = cert.getNotAfter();
                                    String task1 = "";
                                    String task2 = "";
                                    String task3 = "";

                                    // Creo lo scheduling
                                    GregorianCalendar calendar = new GregorianCalendar();
                                    calendar.setTime(date);

                                    task3 = format.format(calendar.getTime());

                                    calendar.roll(GregorianCalendar.DAY_OF_YEAR, false);

                                    task2 = format.format(calendar.getTime());

                                    calendar.roll(GregorianCalendar.DAY_OF_YEAR, false);

                                    task1 = format.format(calendar.getTime());

                                    config.setSchedule(task1 + "|" + task2 + "|" + task3);
                                    config.setSubjectDN(cert.getIssuerX500Principal().getName());

                                    log.debug("Schedule:" + config.getSchedule());

                                    FactorySigner.getInstanceConfigStorage().upsertConfig(config);

                                    // Se il certificato è scaduto recupero ed inserico la CRL se non già presente
                                    X509CRL crl = null;
                                    try {
                                        crl = FactorySigner.getInstanceCRLStorage().retriveCRL(
                                                ((X509Certificate) obj).getSubjectX500Principal().getName(),
                                                SignerUtil.getSubjectKeyId((X509Certificate) obj));
                                    } catch (CryptoStorageException e) {
                                        log.error("errore durante il recupero di una crl", e);
                                    }

                                    if (crl == null) {
                                        // Recupero ed inserisco la CRL
                                        try {
                                            List<String> urlCRLDistributionPoints = SignerUtil.newInstance()
                                                    .getURLCrlDistributionPoint((X509Certificate) obj);
                                            crl = SignerUtil.newInstance().getCrlByURL(urlCRLDistributionPoints);
                                            if (crl != null) {
                                                FactorySigner.getInstanceCRLStorage().upsertCRL(crl);
                                            }
                                        } catch (CryptoSignerException e) {
                                            log.warn("Warning recupero CRL!", e);
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    log.error("update errore", e);
                }
                log.info("update END");
            } catch (CryptoStorageException e) {
                log.error("Errore Inserimento CA", e);
            }
        }
    }
}