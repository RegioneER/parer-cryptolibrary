package it.eng.crypto.utils;

/**
 *
 * @author Quaranta_M
 */
public class VerificheEnums {

    public enum TipoFirma {

        AVANZATA, QUALIFICATA, DIGITALE
    }

    public enum TipoMarca {

        A_NORMA, SEMPLICE
    }

    public enum EsitoControllo {

        POSITIVO("Controllo OK"), //
        NEGATIVO("Controllo fallito"), //
        WARNING("Controllo con Warning"), //
        NON_ESEGUITO("Non eseguito perchè il formato non è conforme"), //
        FORMATO_NON_CONOSCIUTO, //
        FORMATO_NON_CONFORME, //
        NON_AMMESSO_DELIB_45_CNIPA, //
        DISABILITATO("Il controllo è disabilitato"), //
        NON_NECESSARIO("Il controllo non è necessario"), //
        ERRORE("Controllo non svolto per errore del sistema"), //
        CERTIFICATO_ERRATO("Il certificato non è un certificato di firma"), //
        CERTIFICATO_NON_VALIDO("Il certificato non è ancora valido"), //
        CERTIFICATO_REVOCATO("Il certificato è stato revocato o sospeso"), //
        CERTIFICATO_SCADUTO("Il certificato è scaduto"), //
        CERTIFICATO_SCADUTO_3_12_2009(
                "Il controllo non è svolto perché la CRL non è disponibile ed il certificato è scaduto prima del 3/12/2009"), //
        CRL_NON_SCARICABILE("Il controllo non è svolto perché la CRL non è scaricabile dal server"), //
        CRL_NON_VALIDA("Il controllo non è svolto perché la CRL non è valida"), //
        CRL_SCADUTA("Il controllo non è svolto perché la CRL scaricata è scaduta"), //
        SCONOSCIUTO;

        private final String message;

        private EsitoControllo() {
            this.message = null;
        }

        private EsitoControllo(final String message) {
            this.message = message;
        }

        public java.lang.String message() {
            return this.message;
        }
    }

    public enum FormatoFirmaMarca {

        CADES, CADES_T, M7M, PADES, PDF, P7M, XADES, XADES_T, XML_SIG, TSR, TST
    }

    public enum TipoFileEnum {

        CERTIF_CA, CERTIF_FIRMATARIO, CRL
    }

    public enum TipoControlli {

        CRITTOGRAFICO, CERTIFICATO, CATENA_TRUSTED, CRL, CATENA_TRUSTED_ABILITATO, CRITTOGRAFICO_ABILITATO
    }

    public enum TipoControlliMarca {

        CRITTOGRAFICO, CERTIFICATO, CATENA_TRUSTED, CRL
    }

    public enum TipoVerifica {

        CHIUSURA, CONSERVAZIONE
    }

    public enum TipoRifTemporale {

        DATA_FIRMA, DATA_VERS, MT_VERS_NORMA, MT_VERS_SEMPLICE, RIF_TEMP_VERS
    }
}
