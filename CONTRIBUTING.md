# Contributing

1. Środowisko: Python 3.11+, `pip install -e ".[dev]"`.
2. Przed commitem: `ruff check src tests scripts && ruff format --check src tests scripts && mypy src && pytest`.
3. Testy używają wyłącznie danych **syntetycznych** i mockowanego API; nigdy nie dodawaj prawdziwych certyfikatów, kluczy, haseł, tokenów ani danych podmiotów.
4. Nie wykonuj operacji na produkcyjnym API KSeF.
5. Commity: krótki, rzeczowy temat (`fix: ...`, `feat: ...`, `test: ...`, `docs: ...`, `chore: ...`).
6. Nie zmieniamy: nazwy repozytorium `KSeF-cert-verify`, pakietu `ksef_cert_verify`, polecenia `ksef-cert-verify`, `AppId` instalatora.
7. Zgłaszanie podatności: zob. [SECURITY.md](SECURITY.md).
