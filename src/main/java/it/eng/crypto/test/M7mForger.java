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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.encoders.Base64Encoder;

/**
 * Classe di utilità per la creazione di un file M7M Passi da seguire per creare un M7M: - Crea un
 * P7M (FileProtector) - Crea un TSR dal P7M (FileProtector, timestamp service:
 * http://www.tecnes.com/javasign/timestamp) - Configura i percorsi e crea l'M7M con m7mForger
 */
public class M7mForger {

    private static final String DOC = "C:\\tmp\\firma\\M7M\\verticale\\PRM.pdf.p7m";
    private static final String P7M = DOC + ".p7m";
    private static final String TSR = P7M + ".tsr";
    private static final String M7M = DOC + ".m7m";
    private static final File P7MFile = new File(P7M);
    private static final File TSRFile = new File(TSR);
    private static final File M7MFile = new File(M7M);

    /**
     * @param args
     *
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {

        int p7mSize = (int) P7MFile.length();
        byte[] p7mContent = new byte[p7mSize];
        FileInputStream p7mIS = new FileInputStream(P7MFile);
        p7mIS.read(p7mContent, 0, p7mSize);
        p7mIS.close();

        int tsrSize = (int) TSRFile.length();
        byte[] tsrContent = new byte[tsrSize];
        FileInputStream tsrIS = new FileInputStream(TSRFile);
        tsrIS.read(tsrContent, 0, tsrSize);
        tsrIS.close();

        FileOutputStream m7mOS = new FileOutputStream(M7MFile);
        saveM7m(m7mOS, P7M, p7mContent, TSR, tsrContent);
        m7mOS.flush();
        m7mOS.close();
    }

    private static void saveM7m(OutputStream fos, String p7mName, byte[] p7mContent, String tsrName,
            byte[] tsrContent) throws IOException {
        String mimeBoundary = "Test";
        String mimeHeader = "Mime-Version: 1.0\nContent-Type: multipart/mixed; boundary=\""
                + mimeBoundary + "\"";

        String p7mContentType = "Content-Type: application/pkcs7-mime; smime-type=signed-data; name=\""
                + p7mName + "\"";
        String p7mContentTransferEncoding = "Content-Transfer-Encoding: binary";
        String p7mContentDisposition = "Content-Disposition: attachment; filename=\"" + p7mName
                + "\"";
        String p7mContentDescription = "Content-Description: Signed envelope";

        String tsrContentType = "Content-Type: application/timestamp-reply; name=\"" + tsrName
                + "\"";
        String tsrContentTransferEncoding = "Content-Transfer-Encoding: base64";
        String tsrContentDisposition = "Content-Disposition: attachment; filename=\"" + tsrName
                + "\"";
        String tsrContentDescription = "Content-Description: time-stamp response";

        fos.write(mimeHeader.getBytes());
        fos.write("\r\n".getBytes());
        fos.write("\r\n".getBytes());

        fos.write(("--" + mimeBoundary).getBytes());
        fos.write("\r\n".getBytes());

        fos.write(p7mContentType.getBytes());
        fos.write("\r\n".getBytes());
        fos.write(p7mContentTransferEncoding.getBytes());
        fos.write("\r\n".getBytes());
        fos.write(p7mContentDisposition.getBytes());
        fos.write("\r\n".getBytes());
        fos.write(p7mContentDescription.getBytes());
        fos.write("\r\n".getBytes());
        fos.write("\r\n".getBytes());

        fos.write(p7mContent);
        fos.write("\r\n".getBytes());

        fos.write(("--" + mimeBoundary).getBytes());
        fos.write("\r\n".getBytes());

        fos.write(tsrContentType.getBytes());
        fos.write("\r\n".getBytes());
        fos.write(tsrContentTransferEncoding.getBytes());
        fos.write("\r\n".getBytes());
        fos.write(tsrContentDisposition.getBytes());
        fos.write("\r\n".getBytes());
        fos.write(tsrContentDescription.getBytes());
        fos.write("\r\n".getBytes());
        fos.write("\r\n".getBytes());

        Base64Encoder encoder = new Base64Encoder();
        encoder.encode(tsrContent, 0, tsrContent.length, fos);
        fos.write("\r\n".getBytes());

        fos.write(("--" + mimeBoundary + "--").getBytes());
        fos.write("\r\n".getBytes());
    }
}
