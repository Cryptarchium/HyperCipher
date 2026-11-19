# 🛡️ Dummy App (PyOuro Basic Example)

Questo è un esempio minimale per comprendere come PyOuro protegge il flusso di esecuzione e gestisce le licenze.

L'applicazione è composta da due file:
- `app.py`: Il punto di ingresso principale che controlla se l'ambiente è protetto e se esiste una licenza valida.
- `core.py`: Un modulo fittizio che rappresenta il nucleo segreto della tua applicazione.

## Come testare questo esempio

### 1. Inizializzare il Progetto
Genera le chiavi crittografiche e il file d'ordine segreto:
```bash
pyouro init --entry-point app.py --payload app.py
```
> [!NOTE]
> Specificando `app.py` sia come entry-point che come payload, diciamo al Bootloader di avviare il blocco `if __name__ == "__main__":` contenuto in `app.py`. Il file `core.py` verrà individuato automaticamente come dipendenza e compilato (Cythonizzato).

### 2. Compilare l'Applicazione
Costruisci la versione protetta dell'applicazione:
```bash
pyouro build
```

### 3. Esecuzione senza Licenza
Se provi ad avviare l'applicazione appena compilata:
```bash
.pyouro/build_stage/dist/ProtectedApp/ProtectedApp.exe
```
Vedrai che PyOuro rileverà la mancanza del file `license.sig` e l'applicazione stamperà un messaggio di errore o avvierà una "demo mode", terminando poi l'esecuzione protetta.

### 4. Generare una Licenza
Copia l'Hardware ID stampato a schermo nel passaggio precedente e genera una licenza valida per la tua macchina:
```bash
pyouro license --hw-id "IL_TUO_HARDWARE_ID" --type FULL
```
Questo creerà il file `license.sig` nella directory corrente.

### 5. Esecuzione con Licenza
Avvia nuovamente l'applicazione compilata:
```bash
.pyouro/build_stage/dist/ProtectedApp/ProtectedApp.exe
```
Questa volta, `api.verify_license()` avrà successo. L'applicazione riporterà che la licenza è valida e procederà a eseguire in modo trasparente l'algoritmo segreto contenuto in `core.py`.
