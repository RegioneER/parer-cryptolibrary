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

package it.eng.crypto.storage.impl.filesystem;

import it.eng.crypto.exception.CryptoStorageException;
import it.eng.crypto.storage.ICAStorage;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementazione di uno storage di certificati basato su fileSystem
 *
 * @author Michele Rigo
 *
 */
public class FileSystemCAStorage implements ICAStorage, Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    Logger log = LoggerFactory.getLogger(FileSystemCAStorage.class);

    private static final String CA_DIRECTORY = "CA_VALID_CERTIFICATE";
    private static final String FILE_CONFIG_DIRECTORY = "CONFIG";
    private static final String FILE_CONFIG_NAME = "Configuration";

    /**
     * Directory di salvataggio dei certificati
     */
    private String directory;

    /**
     * Recupera il riferimento alla directory di salvataggio dei certificati
     *
     * @return
     */
    public String getDirectory() {
        return directory;
    }

    /**
     * Definisce il riferimento alla directory di salvataggio dei certificati
     *
     * @param directory
     */
    public void setDirectory(String directory) {
        this.directory = directory;
    }

    public void insertCA(X509Certificate certificate) throws CryptoStorageException {
        log.info("insertCA START");
        try {
            File dir = new File(directory + File.separator + CA_DIRECTORY);
            if (!dir.exists()) {
                dir.mkdir();
            }

            // Creo la directory di configurazione
            File dirConfig = new File(dir + File.separator + FILE_CONFIG_DIRECTORY);
            if (!dirConfig.exists()) {
                dirConfig.mkdir();
            }

            // Calcolo MD5 del soggetto
            String fileName = DigestUtils.md5Hex(certificate.getEncoded());
            File file = new File(dir, fileName);
            if (file.exists()) {
                file.delete();
            }

            // Scrivo il nuovo file
            FileUtils.writeByteArrayToFile(file, certificate.getEncoded());

            // Inserisco la configurazione
            boolean active = true;
            try {
                certificate.checkValidity();
                active = true;
            } catch (CertificateExpiredException e) {
                log.warn("Certificato scaduto!");
                active = false;
            } catch (CertificateNotYetValidException e) {
                log.warn("Certificato non più valido!");
                active = false;
            }
            updateConfig(certificate, active, file);
            log.info("insertCA END");
        } catch (Exception e) {
            log.error("Errore inserimento/update Certificato di certificazione!", e);
            throw new CryptoStorageException(
                    "Errore inserimento/update Certificato di certificazione!", e);
        }
    }

    public List<X509Certificate> retriveActiveCA() throws CryptoStorageException {
        log.info("retriveActiveCA START");
        List<X509Certificate> activeCertificates = new ArrayList<X509Certificate>();
        try {
            // Recupero tutte le configurazioni del certificato
            List<CABean> configs = getAllConfig();
            CertificateFactory factorys = CertificateFactory.getInstance("X509",
                    BouncyCastleProvider.PROVIDER_NAME);
            for (int i = 0; i < configs.size(); i++) {
                CABean bean = configs.get(i);
                if (bean.isActive()) {
                    activeCertificates.add((X509Certificate) factorys.generateCertificate(
                            FileUtils.openInputStream(new File(bean.getFilePath()))));
                }
            }
        } catch (Exception e) {
            log.error("Errore recupero certificati attivi!", e);
            throw new CryptoStorageException("Errore recupero certificati attivi!", e);
        }
        log.info("retriveActiveCA END");
        return activeCertificates;
    }

    public X509Certificate retriveCA(X500Principal subject, String keyId)
            throws CryptoStorageException {
        log.info("retriveCA START");
        X509Certificate ret = null;
        CABean bean = getConfig(subject);
        if (bean != null) {
            File file = new File(bean.getFilePath());
            if (file.exists()) {
                try {
                    CertificateFactory factorys = CertificateFactory.getInstance("X509",
                            BouncyCastleProvider.PROVIDER_NAME);
                    ret = (X509Certificate) factorys
                            .generateCertificate(FileUtils.openInputStream(file));
                } catch (Exception e) {
                    log.error("Errore recupero certificato per X500Principal:" + subject.getName(),
                            e);
                    throw new CryptoStorageException(e);
                }
            }
        }
        log.info("retriveCA END");
        return ret;
    }

    public void revokeCA(X509Certificate certificate) throws CryptoStorageException {
        log.info("revokeCA START");
        updateConfig(certificate, false, null);
        log.info("revokeCA END");
    }

    private CABean getConfig(X500Principal principal) {
        log.info("getConfig START");
        // Deserializzo il file per recuperare la lista delle configurazioni
        CABean bean = null;
        File file = new File(directory + File.separator + CA_DIRECTORY + File.separator
                + FILE_CONFIG_DIRECTORY + File.separator + FILE_CONFIG_NAME);
        List<CABean> lista = new ArrayList<CABean>();
        if (file.exists()) {
            try {
                ObjectInputStream input = new ObjectInputStream(FileUtils.openInputStream(file));
                lista = (List<CABean>) input.readObject();
                input.close();
            } catch (Exception e) {
                log.warn("revokeCA WARNING", e);
                lista = new ArrayList<CABean>();
            }
        }
        // Ciclo le configurazioni
        for (int i = 0; i < lista.size(); i++) {
            if (lista.get(i).getSubjectDN().equals(principal.getName())) {
                bean = lista.get(i);
                break;
            }
        }
        log.info("getConfig END");
        return bean;
    }

    private List<CABean> getAllConfig() {
        log.info("getAllConfig START");
        // Deserializzo il file per recuperare la lista delle configurazioni
        CABean bean = null;
        File file = new File(directory + File.separator + CA_DIRECTORY + File.separator
                + FILE_CONFIG_DIRECTORY + File.separator + FILE_CONFIG_NAME);
        List<CABean> lista = new ArrayList<CABean>();
        if (file.exists()) {
            try {
                ObjectInputStream input = new ObjectInputStream(FileUtils.openInputStream(file));
                lista = (List<CABean>) input.readObject();
                input.close();
            } catch (Exception e) {
                log.warn("File non inizializzato, warning di lettura");
                lista = new ArrayList<CABean>();
            }
        }
        log.info("getAllConfig END");
        return lista;
    }

    private void updateConfig(X509Certificate certificate, boolean active, File fileCert) {
        log.info("updateConfig START");
        // Deserializzo il file per recuperare la lista delle configurazioni
        File file = new File(directory + File.separator + CA_DIRECTORY + File.separator
                + FILE_CONFIG_DIRECTORY + File.separator + FILE_CONFIG_NAME);
        List<CABean> lista = new ArrayList<CABean>();
        if (file.exists()) {
            try {
                ObjectInputStream input = new ObjectInputStream(FileUtils.openInputStream(file));
                lista = (List<CABean>) input.readObject();
                input.close();
            } catch (Exception e) {
                log.warn("File non inizializzato, warning di lettura");
                lista = new ArrayList<CABean>();
            }
        }

        boolean newfile = true;

        // Ciclo le configurazioni
        for (int i = 0; i < lista.size(); i++) {
            // if(lista.get(i).getSubjectDN().equals(certificate.getIssuerX500Principal().getName())){
            if (lista.get(i).getSubjectDN()
                    .equals(certificate.getSubjectX500Principal().getName())) {
                newfile = false;
                CABean bean = lista.get(i);
                bean.setActive(active);
                if (fileCert != null) {
                    bean.setFilePath(fileCert.getAbsolutePath());
                }
                lista.set(i, bean);
            }
        }
        if (newfile) {
            CABean bean = new CABean();
            bean.setActive(active);
            bean.setFilePath(file.getAbsolutePath());
            // bean.setSubjectDN(certificate.getIssuerX500Principal().getName());
            bean.setSubjectDN(certificate.getSubjectX500Principal().getName());
            lista.add(bean);
        }

        try {
            // Serializzo la lista
            FileOutputStream fileConfig = new FileOutputStream(file);
            ObjectOutputStream streamOut = new ObjectOutputStream(fileConfig);
            streamOut.writeObject(lista);
            streamOut.flush();
            streamOut.close();
        } catch (IOException e) {
            log.warn("File non inizializzato, warning di scrittura");
        }
        log.info("updateConfig END");
    }

    public boolean isActive(X509Certificate certificate, String keyId)
            throws CryptoStorageException {
        log.info("isActive START");
        // Deserializzo il file per recuperare la lista delle configurazioni
        File file = new File(directory + File.separator + CA_DIRECTORY + File.separator
                + FILE_CONFIG_DIRECTORY + File.separator + FILE_CONFIG_NAME);
        boolean active = false;
        if (file.exists()) {
            try {
                ObjectInputStream input = new ObjectInputStream(FileUtils.openInputStream(file));
                List<CABean> lista = (List<CABean>) input.readObject();
                input.close();
                // Ciclo le configurazioni
                for (int i = 0; i < lista.size(); i++) {
                    if (lista.get(i).getSubjectDN()
                            .equals(certificate.getSubjectX500Principal().getName())) {
                        CABean bean = lista.get(i);
                        active = bean.isActive();
                        break;
                    }
                }
            } catch (Exception e) {
                log.warn("Errore controllo dello stato del certificato");
            }
        }
        log.info("isActive END");
        return active;
    }
}
