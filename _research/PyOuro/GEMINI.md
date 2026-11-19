# GEMINI.md — PyOuro Development Guide

> **PyOuro** è una libreria Python per il packaging crittografico di applicazioni desktop. Compila il codice sorgente con Cython, genera un bootloader crittografico, firma digitalmente i moduli e li impacchetta con PyInstaller in un eseguibile standalone.

---

## Architettura del Progetto

```
pyouro/
├── builder/
│   ├── build_cmd.py          # Orchestratore principale della build
│   ├── config_validator.py   # Validazione formale di pyouro.toml / yaml / json
│   ├── dependency_analyzer.py # Analisi AST per la discovery automatica delle dipendenze
│   ├── bootloader_template.py # Template del bootloader crittografico (iniettato al runtime)
│   ├── compiler.py           # Wrapper Cython per .py → .pyd
│   └── payload.py            # Gestione del payload cifrato
├── core/
│   ├── init_cmd.py           # Logica per 'pyouro init'
│   ├── build_cmd.py          # Entry point CLI per 'pyouro build'
│   ├── diagnostics.py        # Crash reporter centralizzato (logs/ locale)
│   ├── hardware.py           # Fingerprinting hardware (HW-ID)
│   ├── keyring_mgr.py        # Gestione keyring multi-piattaforma
│   ├── license_cmd.py        # Generazione e verifica licenze RSA-PSS
│   └── doctor_cmd.py         # Diagnostica ambiente 'pyouro doctor'
└── crypto/
    ├── vault.py              # Cifratura AES-GCM + derivazione chiave HKDF
    └── padding.py            # Generazione moduli di padding pseudo-casuali
```

---

## Principi Architetturali (NON derogare)

### 1. Niente "pezze" — Root Cause Analysis
Ogni bug va analizzato alla sua causa originale. Non applicare hotfix ad-hoc su casi specifici. Chiedersi sempre:
- *Perché* succede?
- *Dove* nel ciclo di vita della build avviene?
- *Come* si può prevenire strutturalmente?

### 2. Ordine cronologico del Build Pipeline
Il pipeline di build ha un ordine preciso e le fasi **non sono intercambiabili**:

```
1. ConfigValidator   → legge pyouro.toml, file_order.json, prod_secrets.yaml
2. DependencyAnalyzer → scansiona .py con AST (PRIMA che Cython li elimini!)
3. compile_modules   → Cython compila .py → .pyd (i .py spariscono)
4. bootloader        → inietta il bootloader crittografato
5. PyInstaller       → impacchetta tutto con --collect-all cryptography/keyring
```

> ⚠️ **Critico**: `DependencyAnalyzer.get_all_dependencies()` DEVE essere chiamato PRIMA di `compile_modules()`. Cython elimina i file `.py` sorgenti — se l'analisi AST avviene dopo, non troverà nulla.

### 3. Moduli nuovi = file separati
Ogni responsabilità vive nel suo modulo:
- `ConfigValidator` → validazione config (non sparsa in `build_cmd.py`)
- `DependencyAnalyzer` → AST analysis (non inlined)
- `Diagnostics` → crash logging (non `os._exit(1)` nudo)

### 4. Configurazione dall'esterno, non hardcoded
**Qualsiasi** comportamento configurabile di PyInstaller deve essere esposto in `pyouro.toml`. Mai hardcodare opzioni nel codice. Il file `pyouro.toml` è l'unica fonte di verità.

---

## pyouro.toml — Schema Completo

```toml
[app]
name = "MyApp"
version = "1.0.0"
entry_point = "main.py"

[payload]
file = "app.py"
entry_function = "bootstrap"

[security]
anti_debug = true

[build]
noconsole = true                   # Nasconde la finestra console (app GUI)
icon = "assets/icon.ico"          # Icona dell'eseguibile
force_include = ["customtkinter"] # Moduli da includere forzatamente
pyinstaller_args = []             # Flags aggiuntivi per PyInstaller
```

> I parametri in `[build]` vengono letti da `build_cmd.py` e passati dinamicamente a PyInstaller. Non modificare mai `build_cmd.py` direttamente per configurazioni applicative.

---

## Dipendenze Problematiche (Nota Tecnica)

### `cryptography` (Rust/C Extension)
Questa libreria usa caricamento dinamico dei sottomoduli `hazmat`. `--hidden-import` da solo **non basta**. Usare sempre:
```python
cmd.extend(["--collect-all", "cryptography"])
```
Questo copia l'intera cartella della libreria nell'eseguibile, prevenendo `ModuleNotFoundError: cryptography.hazmat.primitives.kdf`.

### `keyring` (Backend multipli)
Stessa situazione — dipendenze platform-specific caricate a runtime. Usare:
```python
cmd.extend(["--collect-all", "keyring"])
```

### Moduli Cython (`.pyd`)
Dopo la compilazione, i nomi dei file contengono il tag di architettura (`module.cp314-win_amd64.pyd`). Il bootloader usa `p.name.split('.')[0]` per normalizzare il nome e riconciliare la mappa degli hash.

---

## Sistema di Diagnostica

Il modulo `pyouro.core.diagnostics` è il crash reporter centralizzato. **Non usare mai `os._exit(1)` diretto** in nessun modulo.

```python
from pyouro.core.diagnostics import pyouro_crash_reporter

try:
    # ... codice critico ...
except Exception as e:
    pyouro_crash_reporter(app_name, e)  # Scrive in logs/ locale, poi termina
```

### Percorso dei log
- **App frozen (PyInstaller)**: `<cartella_exe>/logs/<AppName>_crash.log`
- **Sviluppo**: `<cwd>/logs/<AppName>_crash.log`

Nessun file in `AppData` o path di sistema. I log devono essere visibili e accessibili all'utente finale senza cercare.

---

## Ciclo di Sviluppo e Release

### Prima di ogni commit
```powershell
python -m unittest discover -s tests
```
I 26 test devono passare tutti (OK). Mai committare con test falliti.

### Versionamento
Usa semantic versioning. Bump in `setup.py`:
- **Patch** (1.2.x): bugfix, nessuna breaking change API
- **Minor** (1.x.0): nuova feature backward-compatible (es. nuove opzioni `pyouro.toml`)
- **Major** (x.0.0): breaking changes nell'API pubblica o nel formato `pyouro.toml`

### Release su PyPI
```powershell
# 1. Bump versione in setup.py
# 2. Commit + push
git add .; git commit -m "feat/fix: descrizione (vX.Y.Z)"; git push

# 3. Build
Remove-Item -Recurse -Force build, dist, pyouro.egg-info -ErrorAction SilentlyContinue
python setup.py sdist bdist_wheel

# 4. Upload
python -m twine upload dist/*
```

> Il primo tentativo di upload per una versione già esistente ritorna 403 Forbidden — è normale se stai ritentando con la stessa versione. Bumpa il numero.

---

## Regole per le Modifiche al Build Pipeline

| Area | File da modificare | File da NON modificare |
|---|---|---|
| Nuove opzioni di config | `config_validator.py`, `build_cmd.py`, `init_cmd.py` (template toml) | Nulla in site-packages |
| Nuove dipendenze auto-rilevate | `dependency_analyzer.py` | `build_cmd.py` (non aggiungere hardcoded) |
| Crash handling | `diagnostics.py` | I singoli moduli (solo chiamare il reporter) |
| Comportamento PyInstaller | `build_cmd.py` + opzioni `[build]` in toml | Nulla fuori da PyOuro |

---

## Anti-Pattern da Evitare

```python
# ❌ SBAGLIATO: patch manuale in site-packages
# Non modificare mai i file dentro il venv del progetto cliente

# ❌ SBAGLIATO: split del modulo al top-level
imports.add(alias.name.split('.')[0])  # perde i sottomoduli hazmat!

# ❌ SBAGLIATO: analisi AST dopo Cython
compile_modules(...)  # i .py spariscono!
ast_deps = DependencyAnalyzer.get_all_dependencies(...)  # troppo tardi!

# ❌ SBAGLIATO: crash silenzioso
except Exception:
    os._exit(1)  # nessun log, nessuna traccia

# ✅ CORRETTO
except Exception as e:
    pyouro_crash_reporter(app_name, e)
```

---

## Comandi Utili

```powershell
# Test completo
python -m unittest discover -s tests

# Build e test locale del pacchetto
pip install -e .
pyouro init --entry main.py --payload app.py
pyouro build

# Verifica dipendenze estratte dall'AST
python -c "
from pyouro.builder.dependency_analyzer import DependencyAnalyzer
from pathlib import Path
print(DependencyAnalyzer.get_all_dependencies(Path('.'), ['app.py']))
"
```
