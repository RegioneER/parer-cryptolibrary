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

package it.eng.crypto.storage.impl.filesystem;

import it.eng.crypto.exception.CryptoStorageException;
import it.eng.crypto.storage.ICRLStorage;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.X509Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implmentazione di uno storage di CRL basato su file system
 *
 * @author Michele Rigo
 *
 */
public class FileSystemCRLStorage implements ICRLStorage {

    Logger log = LoggerFactory.getLogger(FileSystemCRLStorage.class);

    private static final String CA_DIRECTORY = "CRL_LIST";
    private static final String FILE_CONFIG_DIRECTORY = "CONFIG";
    private static final String FILE_CONFIG_NAME = "Configuration";

    /**
     * Directory di salvataggio dei certificati
     */
    private String directory;

    public void upsertCRL(X509CRL crl) throws CryptoStorageException {
        log.info("insertCRL START");
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
            String fileName = DigestUtils.md5Hex(crl.getEncoded());
            File file = new File(dir, fileName);
            if (file.exists()) {
                file.delete();
            }

            // Scrivo il nuovo file
            FileUtils.writeByteArrayToFile(file, crl.getEncoded());

            updateConfig(crl, file);
        } catch (Exception e) {
            log.error("Errore insertCRL!", e);
            throw new CryptoStorageException("Errore aggiunta Certificato", e);
        }
        log.info("insertCRL END");
    }

    public X509CRL retriveCRL(String subjectDN, String keyId) throws CryptoStorageException {
        log.info("retriveCRL START");
        // Controllo se il certificato è valido alla data attuale
        X509CRL crl = null;

        // Recupero la configurazione per il certificato
        CRLBean config = getConfig(subjectDN);
        if (config != null) {
            String filePath = config.getFilePath();
            try (FileInputStream stream = new FileInputStream(filePath)) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                crl = (X509CRL) cf.generateCRL(stream);
            } catch (Exception e) {
                log.error("Errore retriveCRL!", e);
                throw new CryptoStorageException(e);
            }
        } else {

            return null;
        }

        log.info("retriveCRL END");
        return crl;
    }

    /**
     * Recupera la directory di salvataggio dei certificati
     *
     * @return
     */
    public String getDirectory() {
        return directory;
    }

    /**
     * Definisce la directory di salvataggio dei certificati
     *
     * @param directory
     */
    public void setDirectory(String directory) {
        this.directory = directory;
    }

    private CRLBean getConfig(String subjectDN) {
        log.info("getConfig START");
        X509Principal subjectPrincipal = new X509Principal(subjectDN);
        // Deserializzo il file per recuperare la lista delle configurazioni
        CRLBean bean = null;
        File file = new File(directory + File.separator + CA_DIRECTORY + File.separator + FILE_CONFIG_DIRECTORY
                + File.separator + FILE_CONFIG_NAME);
        List<CRLBean> lista = new ArrayList<CRLBean>();
        if (file.exists()) {
            try {
                ObjectInputStream input = new ObjectInputStream(FileUtils.openInputStream(file));
                lista = (List<CRLBean>) input.readObject();
                input.close();
            } catch (Exception e) {
                log.warn("getConfig warning lettura file serializzato!", e);
                lista = new ArrayList<CRLBean>();
            }
        }
        // Ciclo le configurazioni
        for (int i = 0; i < lista.size(); i++) {
            X509Principal principal = new X509Principal(lista.get(i).getSubjectDN());
            if (principal.equals(subjectPrincipal, false)) {
                bean = lista.get(i);
                break;
            }
        }
        log.info("getConfig END");
        return bean;
    }

    private void updateConfig(X509CRL crl, File fileCert) {
        log.info("updateConfig START");
        // Deserializzo il file per recuperare la lista delle configurazioni
        File file = new File(directory + File.separator + CA_DIRECTORY + File.separator + FILE_CONFIG_DIRECTORY
                + File.separator + FILE_CONFIG_NAME);
        List<CRLBean> lista = new ArrayList<CRLBean>();
        if (file.exists()) {
            try {
                ObjectInputStream input = new ObjectInputStream(FileUtils.openInputStream(file));
                lista = (List<CRLBean>) input.readObject();
                input.close();
            } catch (Exception e) {
                log.warn("updateConfig warning lettura file serializzato!", e);
                lista = new ArrayList<CRLBean>();
            }
        }

        boolean newfile = true;

        // Ciclo le configurazioni
        for (int i = 0; i < lista.size(); i++) {
            if (lista.get(i).getSubjectDN().equals(crl.getIssuerX500Principal().getName())) {
                newfile = false;
                CRLBean bean = lista.get(i);
                if (fileCert != null) {
                    bean.setFilePath(fileCert.getAbsolutePath());
                }
                lista.set(i, bean);
            }
        }
        if (newfile) {
            CRLBean bean = new CRLBean();
            bean.setFilePath(file.getAbsolutePath());
            bean.setSubjectDN(crl.getIssuerX500Principal().getName());
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
            log.warn("updateConfig warning scrittura file serializzato!", e);
        }
        log.info("updateConfig END");
    }
}
