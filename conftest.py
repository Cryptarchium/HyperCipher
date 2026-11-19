# -*- coding: utf-8 -*-
"""pytest conftest: V5.3 zafiyet raporu [1] fix'inin test tarafi opt-in'i.

_encrypt_deterministic / _encrypt_file_deterministic (sabit salt/nonce ile
nonce-reuse footgun'i) varsayilan olarak FAIL-CLOSED (RuntimeError) olacak
sekilde _DETERMINISTIC_MODE=False tasarlanmistir. Bu bayrak YALNIZCA test
ortaminda acilir:

  - pytest altinda bu dosya otomatik yuklenir (isaretli testler calisir).
  - `python -m unittest` altinda conftest yuklenmez; deterministic API
    kullanan test dosyalarinin (test_hyper_cipher.py, test_professional.py)
    basinda kendi opt-in satirlari vardir.
  - Uretim kodu / hcli.py bu bayraga DOKUNMAMALIDIR.

NOT: Bu dosya URETIM paketi degildir; yalnizca test kurulumudur.
"""

import hyper_cipher as hc

hc._DETERMINISTIC_MODE = True
