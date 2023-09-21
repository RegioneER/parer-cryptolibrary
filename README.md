# Cryptolibrary

Fonte template redazione documento:  https://www.makeareadme.com/.


# Descrizione

Cryptolibrary è una libreria realizzata al fine di implementare logiche di verifica di file digitalmente firmati. Utilizzata come **dipendenza** dal microservizio Verifica firma Crypto.
# Installazione

Come già specificato nel paragrafo precedente [Descrizione](# Descrizione) si tratta di un progetto di tipo "libreria", quindi un modulo applicativo utilizzato attraverso la definzione della dipendenza Maven secondo lo standard previsto (https://maven.apache.org/): 

```xml
<dependency>
    <groupId>it.eng.parer</groupId>
    <artifactId>cryptolibrary</artifactId>
    <version>$VERSIONE</version>
</dependency>
```

# Utilizzo

Il modulo definisce le logiche di verifica di firme digitali dei formati noti (vedi ETSI https://www.etsi.org/), permette quindi di stabilire se la firma applicata è valida o meno estrapolandone un "macro set" di meta informazioni. Da sottolineari, che non tutti i formati noti sono validati, come ad esempio ASIC (https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf), che non è compatibili con le logiche di verifica della cryptolibrary (per ovviare a questo "limite" è stato introdotto il sistema di validazione firme DSS-EIDAS).
L'utilizzo della suddetta libreria è legato al microservizio CRYPTO il quale la utilizza come logical core business per le verifiche da effettuare sui file firmati.

# Supporto

Progetto a cura di [Engineering Ingegneria Informatica S.p.A.](https://www.eng.it/).

# Contributi

Se interessati a crontribuire alla crescita del progetto potete scrivere all'indirizzo email <a href="mailto:areasviluppoparer@regione.emilia-romagna.it">areasviluppoparer@regione.emilia-romagna.it</a>.

# Autori

Proprietà intellettuale del progetto di [Regione Emilia-Romagna](https://www.regione.emilia-romagna.it/) e [Polo Archivisitico](https://poloarchivistico.regione.emilia-romagna.it/).

# Licenza

Questo progetto è rilasciato sotto licenza GNU Affero General Public License v3.0 or later ([LICENSE.txt](LICENSE.txt)).
