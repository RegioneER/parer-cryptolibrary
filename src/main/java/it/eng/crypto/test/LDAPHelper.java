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

import java.security.Security;
import java.security.cert.CertStore;
import java.util.Hashtable;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

// import org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509CRLStoreSelector;
import org.bouncycastle.x509.X509CertStoreSelector;
import org.bouncycastle.x509.util.LDAPStoreHelper;

/**
 * CLASSE PER CLASSE PER ACCESSO LDAP
 *
 * @version 1.1
 */
public class LDAPHelper {

    // VARIABILI UTILIZZATE
    private Hashtable env = new Hashtable();
    private String user = "";
    private String password = "";
    private String provider_url = "";
    private String ou = "";
    private String dc = "";

    /**
     * METODO COSTRUTTORE PER LA CONNESSIONE <br>
     * Il metodo definisce tutte le variabili necessarie e richiama il metodo per preparare la
     * connessione
     *
     * @param usr          User di accesso a LDAP
     * @param psw          Password di accesso a LDAP
     * @param provider_url URL a cui connettersi
     * @param ou           OU di LDAP
     * @param dc           dc di LDAP
     */
    public LDAPHelper(String usr, String psw, String provider_url, String ou, String dc) {
        this.user = usr;
        this.password = psw;
        this.provider_url = provider_url;
        this.ou = ou;
        this.dc = dc;
        prepareConnection();
    }

    /**
     * METODO PER PREPARARE LA CONNESSIONE <br>
     * Il metodo prepara l'oggetto necessario alla connessione
     */
    private void prepareConnection() {
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://" + provider_url);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "CN=" + dc);
        // env.put(Context.SECURITY_CREDENTIALS, password);
    }

    /**
     * METODO PER CONTROLLARE SE CI SI RIESCE A CONNETTERE A LDAP <br>
     * Il metodo verifica se ci si riesce a connettere a LDAP con le variabili di classe valorizzate
     * con il metodo costruttore
     */
    public boolean userVerify() {
        boolean userVerify = false;
        try {
            DirContext authContext = new InitialDirContext(env);

            userVerify = true;
            authContext.close();
        } catch (AuthenticationException authEx) {
            authEx.printStackTrace();
            // System.out.println("Authentication failed!");
            userVerify = false;
        } catch (NamingException namEx) {
            namEx.printStackTrace();
            // System.out.println("Something went wrong!");
            userVerify = false;
        }
        return userVerify;
    }

    /**
     * METODO PER LA LETTURA DI UN PARAMETRO SU LDAP <br>
     * Il metodo ricerca un parametro per l'utente specificato e ne restituisce il rispettivo valore
     *
     * @param paramToResearch Parametro da cercare
     *
     * @return Restituisce il valore del parametro cercato
     *
     * @exception Il metodo restituisce ""
     */
    public String retriveParameter(String paramToResearch) {
        String returnValue = "";
        try {
            DirContext ctx = new InitialDirContext(env);
            String results;
            String[] sAttrIDs = new String[1];
            sAttrIDs[0] = paramToResearch;

            /* Get the attributes requested */

            Attributes aAnswer = ctx.getAttributes(env.get(Context.SECURITY_PRINCIPAL).toString(),
                    sAttrIDs);
            NamingEnumeration enumUserInfo = aAnswer.getAll();
            while (enumUserInfo.hasMoreElements()) {
                results = (enumUserInfo.nextElement().toString());
                returnValue = results.substring(6);
            }
        } catch (NamingException e) {
            System.out.println(e.getMessage());
        }
        return returnValue;
    }

    /**
     * METODO PER LA LETTURA DI UN PARAMETRO SU LDAP SPECIFICANDO UN UTENTE <br>
     * Il metodo ricerca un parametro per l'utente specificato e ne restituisce il rispettivo valore
     *
     * @param userName        Utente su cui cercare un parametro
     * @param paramToResearch Parametro da cercare
     *
     * @return Restituisce il valore del parametro cercato
     *
     * @exception Il metodo restituisce ""
     */
    public String retriveParameter(String userName, String paramToResearch) {

        String indirizzoMail = "";
        try {
            DirContext ctx = new InitialDirContext(env);
            String results;
            String[] sAttrIDs = new String[1];
            sAttrIDs[0] = paramToResearch;

            /* Get the attributes requested */
            Attributes aAnswer = ctx.getAttributes("CN=" + userName + "," + ou + "," + dc,
                    sAttrIDs);
            NamingEnumeration enumUserInfo = aAnswer.getAll();
            while (enumUserInfo.hasMoreElements()) {
                results = (enumUserInfo.nextElement().toString());
                indirizzoMail = results.substring(6);
            }
        } catch (NamingException e) {
            System.out.println(e.getMessage());
        }
        return indirizzoMail;
    }

    /**
     * METODO PER LA SCRITTURA A VIDEO DI TUTTI I PARAMETRI <br>
     * Il metodo scrive a video tutti i parametri assegnati all'utente con cui si effettua la
     * connessione
     */
    public void writeListParameter() {
        try {
            DirContext ctx = new InitialDirContext(env);
            String results;
            Attributes aAnswer = ctx.getAttributes(env.get(Context.SECURITY_PRINCIPAL).toString());
            NamingEnumeration enumUserInfo = aAnswer.getAll();
            while (enumUserInfo.hasMoreElements()) {
                results = (enumUserInfo.nextElement().toString());
                System.out.println(results);
            }
        } catch (NamingException e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     * METODO PER LA SCRITTURA A VIDEO DI TUTTI I PARAMETRI DI UN UTENTE SPECIFICO <br>
     * Il metodo scrive a video tutti i parametri assegnati ad un utente specifico
     *
     * @param username Utente per cui ricercare tutti i parametri
     */
    public void writeListParameter(String userName) {
        try {
            DirContext ctx = new InitialDirContext(env);
            String results;
            Attributes aAnswer = ctx.getAttributes("CN=" + userName + "," + ou + "," + dc);
            NamingEnumeration enumUserInfo = aAnswer.getAll();
            while (enumUserInfo.hasMoreElements()) {
                results = (enumUserInfo.nextElement().toString());
                System.out.println(results);
            }
        } catch (NamingException e) {
            System.out.println(e.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        X509LDAPCertStoreParameters.Builder builder = new X509LDAPCertStoreParameters.Builder(
                "ldap://fe.csp.multicertify.com",
                "o=CNIPA,ou=Actalis CA per Firma Digitale Qualificata");

        LDAPStoreHelper helper = new LDAPStoreHelper(builder.build());

        CertStore cs = CertStore.getInstance("X509LDAP", builder.build(), "BC");

        cs.getCertificates(new X509CertStoreSelector());

        System.out.println(
                helper.getAttributeAuthorityRevocationLists(new X509CRLStoreSelector()).size());
        System.out.println("FINE");

    }
}
