package it.eng.crypto;

import it.eng.crypto.ca.ICertificateAuthority;
import it.eng.crypto.storage.ICAStorage;
import it.eng.crypto.storage.ICRLStorage;
import it.eng.crypto.storage.IConfigStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

/**
 * Classe che definisce la logica di business preposta alle operazioni di registrazione e monitoraggio dei task
 *
 * @author Michele Rigo
 *
 */
public class FactorySigner {

    static Logger log = LoggerFactory.getLogger(FactorySigner.class);
    // /*
    // * Stringa utilizzata per sincronizzare i metodi di start stop.
    // */
    // private static String synchronize = "SINC";
    //

    /**
     * Registra l'ApplicationContext di Spring per il recupero delle configurazioni
     *
     * @param configuration
     */
    public static void registerSpringContext(ApplicationContext context) {
        CryptoSingleton.getInstance().setContext(context);
    }

    // /**
    // * Metodo che registra gli schedulatori sul singleton e cancella quelli
    // * precedentemente registrati Alla chiamata di questo metodo i task attivi
    // * vengono stoppati.
    // */
    // public static void registerTask() throws CryptoSignerException {
    // //Eseguo lo stop di tutti i task presenti sul singleton.
    // stopTask();
    //
    // CryptoConfiguration configuration = CryptoSingleton.getInstance().getConfiguration();
    //
    // //Registro lo scheduler di aggiornamento della CA
    // //Creo un'istanza del listener
    // ListenerUpdateCertificateAuthorityList listenerCA = new ListenerUpdateCertificateAuthorityList();
    //
    // //Creo lo scheduler
    // Scheduler schedulerCA = new Scheduler();
    // schedulerCA.addSchedulerListener(listenerCA);
    // String idCA = schedulerCA.schedule(configuration.getScheduleCAUpdate(), new
    // TaskUpdateCertificateAuthorityList());
    //
    // CryptoSingleton.getInstance().registerSchedule(schedulerCA, idCA, CryptoConstants.CA_UPDATE_TASK);
    //
    // //Registro lo scheduler di aggiornamento del controllo di revoca delle Certification Authority
    // //Creo un'istanza del listener
    // ListenerUpdateCertificateAuthorityRevoke listenerCARevoke = new ListenerUpdateCertificateAuthorityRevoke();
    //
    // //Creo lo scheduler
    // Scheduler schedulerCARevoke = new Scheduler();
    // schedulerCARevoke.addSchedulerListener(listenerCARevoke);
    // String idCARevoke = schedulerCARevoke.schedule(configuration.getScheduleCAUpdate(), new
    // TaskUpdateCertificateAuthorityRevoke());
    //
    // CryptoSingleton.getInstance().registerSchedule(schedulerCARevoke, idCARevoke, CryptoConstants.CA_REVOKE_TASK);
    //
    // //Recupero tutti i distribution point del sistema
    // List<ConfigBean> crlConfig = null;
    // try {
    // crlConfig = getInstanceConfigStorage().retriveAllConfig();
    // } catch (CryptoStorageException e) {
    // log.warn("Warning recupero configurazioni!", e);
    // throw new CryptoSignerException(e);
    // }
    // log.debug("CRL CONFIG:" + crlConfig);
    // if (crlConfig != null) {
    // //Per ogni configurazione registro uno scheduler sul singleton
    // for (int i = 0; i < crlConfig.size(); i++) {
    // //Creo un nuovo task
    // ConfigBean config = crlConfig.get(i);
    // try {
    // TaskUpdateCertificateRevocationList task = new TaskUpdateCertificateRevocationList(config.getCrlURL());
    //
    // //Creo un'istanza del listener
    // ListenerUpdateCertificateRevocationList listener = new
    // ListenerUpdateCertificateRevocationList(config.getSubjectDN());
    //
    // //Creo lo scheduler
    // Scheduler scheduler = new Scheduler();
    // scheduler.addSchedulerListener(listener);
    // String id = scheduler.schedule(config.getSchedule(), task);
    //
    // //Registro lo scheduler sul Singleton
    // CryptoSingleton.getInstance().registerSchedule(scheduler, id, config.getSubjectDN());
    //
    // log.debug("Task Registrato per SubjectDN:" + config.getSubjectDN() + ", con schedulazione:" +
    // config.getSchedule());
    //
    // } catch (Exception e) {
    // log.warn("Warning creazione task per subjectDN:" + config.getSubjectDN(), e);
    // }
    // }
    // }
    // }
    //
    // /**
    // * Avvia i task di aggiornamento dei certificati delle CA
    // *
    // * @throws CryptoSignerException
    // */
    // public static void initialize() throws CryptoSignerException {
    // synchronized (synchronize) {
    // if (CryptoSingleton.getInstance().getContext() == null) {
    // ApplicationContext context = CryptoSignerApplicationContextProvider.getContext();
    // registerSpringContext(context);
    // }
    // getInstanceCertificateAuthority().updateCertificate();
    // }
    // }
    // public static void setup() throws CryptoSignerException {
    // registerTask();
    // initialize();
    // startTask();
    // }
    //
    // /**
    // * Avvia tutti i task di aggiornamento delle CRL presenti sul singleton Se
    // * un task risulta attivo esso viene stoppato e riavviato. Il metodo è
    // * sincornizzato con lo stopTask in modo che non è possibile fermare i task
    // * fino a quando tutti non siano stati avviati.
    // *
    // * @throws CryptoSignerException
    // */
    // public static void startTask() throws CryptoSignerException {
    // synchronized (synchronize) {
    // List<ScheduleBean> schedulers = CryptoSingleton.getInstance().getTasks();
    // for (int i = 0; i < schedulers.size(); i++) {
    // if (schedulers.get(i).getSchedule().isStarted()) {
    // schedulers.get(i).getSchedule().stop();
    // }
    // schedulers.get(i).getSchedule().start();
    // }
    // }
    // }
    //
    // /**
    // * Stoppa tutti i task di aggiornamento delle CRL presenti sul singleton Il
    // * metodo è sincornizzato con lo startTask in modo che non è possibile
    // * fermare i task fino a quando tutti non siano stati avviati.
    // */
    // public static void stopTask() {
    // synchronized (synchronize) {
    // List<ScheduleBean> schedulers = CryptoSingleton.getInstance().getTasks();
    // if (schedulers != null) {
    // for (int i = 0; i < schedulers.size(); i++) {
    // schedulers.get(i).getSchedule().stop();
    // }
    // }
    // }
    // }
    //
    // /**
    // * Ritorna il task corrispondente al subjectDN passato in ingresso
    // *
    // * @param subjectDN
    // * @return
    // */
    // public static synchronized void unregisterTask(String subjectDN) {
    // List<ScheduleBean> schedulers = CryptoSingleton.getInstance().getTasks();
    // Scheduler ret = null;
    // if (schedulers != null) {
    // for (int i = 0; i < schedulers.size(); i++) {
    // if (schedulers.get(i).getSubjectDN().equals(subjectDN)) {
    // schedulers.get(i).getSchedule().stop();
    // schedulers.remove(i);
    // try {
    // getInstanceConfigStorage().deleteConfig(subjectDN);
    // } catch (CryptoStorageException e) {
    // e.printStackTrace();
    // }
    // break;
    // }
    // }
    // }
    // }
    /**
     * Restiruisce un'istanza dello storage delle CA
     *
     * @return
     */
    public static synchronized ICAStorage getInstanceCAStorage() {
        return CryptoSingleton.getInstance().getContext().getBean(CryptoConstants.ICASTORAGE, ICAStorage.class);
    }

    /**
     * Restituisce un'istanza dello storage delle CRL
     *
     * @return
     */
    public static synchronized ICRLStorage getInstanceCRLStorage() {
        return CryptoSingleton.getInstance().getContext().getBean(CryptoConstants.ICRLSTORAGE, ICRLStorage.class);
    }

    /**
     * Restituisce un'istanza dello storage della CONFIG
     *
     * @return
     */
    public static synchronized IConfigStorage getInstanceConfigStorage() {
        return CryptoSingleton.getInstance().getContext().getBean(CryptoConstants.ICONFIGSTORAGE, IConfigStorage.class);
    }

    /**
     * Restituisce un'istanza dello storage della CONFIG
     *
     * @return
     */
    public static synchronized ICertificateAuthority getInstanceCertificateAuthority() {
        return CryptoSingleton.getInstance().getContext().getBean(CryptoConstants.ICERTIFICATEAUTHORITY,
                ICertificateAuthority.class);
    }
}