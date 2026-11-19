# PyOuro: Security Roadmap & Resolved Vulnerabilities

Questo documento raccoglie le vulnerabilità "Out of the Box" (da Red Team Audit) delle versioni pre-1.0.0 e propone soluzioni architetturali di altissimo livello per il futuro, qualora il software protetto diventi un bersaglio di reverse engineer esperti.

## 1. Vulnerabilità: Hooking delle Librerie di Crittografia (Licenze)
**Stato: [RISOLTO]**
**Il Problema Originale**: La verifica della licenza si basava su un controllo booleano (`True/False`) della firma RSA e un semplice `if hw_id == local_hw_id`. Un attaccante poteva falsificare il risultato (Hooking) e usare la licenza su altri computer.
**La Soluzione Implementata (Cryptographic Binding)**: 
- L'Hardware ID del cliente non viene più salvato in chiaro nel file.
- Il server genera una Master Key (256-bit) e la cripta usando l'Hardware ID del cliente come chiave AES.
- Il client usa il proprio Hardware ID per tentare la decrittazione. Se la licenza viene copiata su un altro PC, la matematica dell'AES va in crash crittografico (`InvalidTag`).
- La Master Key sbloccata può essere usata dallo sviluppatore per decriptare database, modelli AI o file di configurazione vitali, rendendo l'attacco booleano completamente inutile.

## 2. Vulnerabilità: Spoofing dell'Hardware ID a Livello OS
**Stato: [IN SOSPESO - FUTURO]**
**Il Problema**: Il modulo `hardware.py` utilizza chiamate e file di sistema (`/sys/class`, Registro di Windows) per leggere l'ID. Un attaccante di altissimo livello (Rootkit) può agganciare le API del sistema operativo per fornire file system fasulli a Python.
**Soluzione Futura**:
- Eliminare del tutto l'uso di moduli di alto livello.
- Scrivere il codice di recupero dell'Hardware ID utilizzando **API native del Kernel in puro C/C++**, compilato direttamente nel file Cython (`hardware.pyd`). Essendo un framework cross-platform, i controlli dovranno essere specifici per OS:
  - **Windows**: Usare chiamate Win32 API in C come `DeviceIoControl` per interrogare direttamente i driver fisici (es. dati SMART del disco) o `GetSystemFirmwareTable` per il BIOS.
  - **Linux**: Effettuare chiamate `ioctl` native in C sui device a blocchi (`/dev/sda`) per i seriali fisici, oppure interrogare direttamente le interfacce di memoria SMBIOS.
  - **macOS**: Utilizzare le API native C++ del framework **IOKit** (`IOServiceGetMatchingService`) per prelevare l'`IOPlatformSerialNumber` direttamente dal kernel XNU.
- Costringendo l'accesso nativo al di sotto del livello utente Python, un attaccante sarebbe obbligato a modificare il Kernel del Sistema Operativo o scrivere driver virtuali (Rootkit) per aggirare il controllo.

## 3. Vulnerabilità: Memory Dumping (Attacco alla RAM OS-Level)
**Stato: [RISOLTO]**
**Il Problema Originale**: Il Bootloader decriptava il payload e lo caricava in memoria con `exec(code_obj)`. Un hacker poteva agganciare al processo un debugger a livello di sistema (es. Cheat Engine, x64dbg, o process dumping) e copiare il `code_obj` decriptato direttamente dalla memoria RAM del computer.
**La Soluzione Implementata (Native OS Anti-Debug)**:
- Il Bootloader interroga direttamente le Syscall a basso livello dell'OS per rilevare i debugger esterni prima della decrittazione.
  - **Windows**: `ctypes.windll.kernel32.IsDebuggerPresent()`.
  - **Linux**: Scansione in C-style del file `/proc/self/status` (controllo del campo `TracerPid`).
  - **macOS**: Chiamata libc `ptrace(PT_DENY_ATTACH)` per respingere attivamente l'iniezione.

## 4. Vulnerabilità: Custom CPython Interpreter
**Stato: [RISOLTO]**
**Il Problema Originale**: Un attaccante poteva scaricare il codice sorgente di Python, alterare il C engine per stampare il bytecode in RAM, compilarlo in una nuova DLL e scambiarla con quella del bundle per intercettare l'esecuzione.
**La Soluzione Implementata (PyInstaller Cross-Platform Binding)**: 
- Aggiunto il target di compilazione standalone (`pyouro build --target onedir`) orchestrato tramite PyInstaller.
- A momento della build, PyOuro trova dinamicamente la libreria di Python installata nel sistema (es. `python310.dll` o `libpython3.X.so`), ne calcola l'hash crittografico e lo inietta segretamente nel Bootloader.
- A runtime, il Bootloader verifica la libreria Python distribuita nel bundle di PyInstaller confrontandola con l'hash iniettato. Se la libreria è stata sostituita per fare "Interpreting Hooking", il sistema va in crash.

## 5. Vulnerabilità: Spoofing del Fallback dell'Hardware ID
**Stato: [RISOLTO]**
**La Soluzione Implementata**: Rimosso ogni blocco di fallback in `hardware.py`. Se l'HW ID non viene recuperato con certezza matematica dal sistema, l'applicazione ora solleva un `RuntimeError` letale (Fail-Secure) e non permette all'utente di aggirare il blocco cambiando il nome del PC.

## 6. Vulnerabilità: Predicibilità del Padding Dinamico
**Stato: [RISOLTO]**
**La Soluzione Implementata**: Ora il padding viene generato usando un `padding_seed.hex` ultra-sicuro a 256 bit creato al momento dell'init, e funzioni deterministiche per impedire l'identificazione basata su espressioni regolari e pattern casuali.

## 7. Vulnerabilità: Estrazione Statica della Permutazione (π)
**Stato: [RISOLTO]**
**La Soluzione Implementata (Hash-Map)**: Il Bootloader non contiene più alcuna lista in chiaro, ma solo un array di Hash crittografici SHA256 incomprensibili. A runtime, scansiona dinamicamente la cartella e ricostruisce la mappa di file e hash in memoria. L'analisi statica è ora impossibile.

## 8. Vulnerabilità: Information Leakage via Static String Analysis
**Stato: [RISOLTO]**
**La Soluzione Implementata (Opaque Failure)**:
- **Bootloader**: Tutti i `print("Fatal Error: ...")` sono stati rimossi. Ogni controllo di protezione che fallisce esegue un `sys.exit(1)` silenzioso, senza rivelare quale guardia ha terminato il processo.
- **`vault.py`**: La stringa descrittiva nella `ValueError` è stata sostituita con il codice opaco `"E01"`. La stringa rivelante `"Error: 'cryptography' library is not installed."` è stata eliminata, sostituita con `sys.exit(1)`.
- **`keyring_mgr.py`**: Rimosso completamente il sistema di logging (`import logging`, `log = getLogger(...)`). Tutte le eccezioni del keyring diventano silenziose (`except Exception: pass`). Rimosso anche il prefisso `"pyouro."` nel namespace del keyring per non rivelare l'identità del framework.
- **Commenti inline**: Rimossi tutti i commenti nel `bootloader_template.py` che descrivevano i layer architetturali.

## 9. Vulnerabilità: RAM e I/O Bottleneck
**Stato: [RISOLTO]**
**La Soluzione Implementata**: Hashing di integrità basato su Chunk I/O NVMe (64 KB) abbattendo il consumo di RAM a una costante e dimezzando i tempi di calcolo dell'integrità.

## 10. Vulnerabilità: Forensica su Disco SSD (Wear Leveling)
**Stato: [RISOLTO]**
**La Soluzione Implementata**: Il compiler non esegue più la copia in chiaro dei sorgenti `.py` nella cartella temporanea `build_stage`, evitando tracce persistenti sui chip NAND degli SSD.

## 11. Vulnerabilità: Corruzione I/O da Race Condition (Time Tampering)
**Stato: [RISOLTO]**
**La Soluzione Implementata**: Introdotto un File Lock (Mutex) cross-platform bloccante con timeout (2 secondi) per prevenire corruzioni da doppio-clic e attacchi locali di Denial of Service sul database temporale.

## 12. Vulnerabilità: Source File Injection
**Stato: [RISOLTO]**
**La Soluzione Implementata**: Il bootloader blocca l'esecuzione se rileva file `.py` o `.pyc` estranei nella directory per impedire l'aggancio a runtime (Hooking).

## 13. Vulnerabilità: Bootloader Replacement (Cryptographic Binding)
**Stato: [RISOLTO]**
**La Soluzione Implementata**: L'hashing a 2 stadi lega l'hash del file `bootloader.pyd` compilato alla chiave crittografica del payload, rendendo impossibile la sostituzione del bootloader senza corrompere l'AES-GCM.

## 14. Vulnerabilità: Attacco Time Rollback (Time Tampering)
**Stato: [RISOLTO]**
**La Soluzione Implementata**: Aggiunto il controllo assoluto di `issued_at` durante la verifica della licenza. Se l'orologio scende sotto la data di rilascio, l'app va in crash, prevenendo l'aggiramento dell'Anti-Rollback anche in caso di formattazione.

## 15. Vulnerabilità: SystemRoot Hijacking (Hardware Spoofing)
**Stato: [RISOLTO]**
**La Soluzione Implementata**: Rimosso il recupero tramite variabili di ambiente per i path di sistema su Windows (es. `powershell.exe`). Path hardcodati e assoluti per prevenire l'iniezione tramite hijacking dell'Environment e rimosso completamente il supporto deprecato alle chiavi container/floating.
