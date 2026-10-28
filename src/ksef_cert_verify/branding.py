"""Nazwa produktu wyświetlana użytkownikowi.

UWAGA: to tylko warstwa prezentacji. NIE zmieniają się: nazwa repozytorium (KSeF-cert-verify), pakiet Python
(`ksef_cert_verify`), polecenie CLI (`ksef-cert-verify`), identyfikatory wewnętrzne (klucze QSettings, `AppId`
instalatora Inno Setup, nazwy pakietów RPM/DEB).
"""

PRODUCT_NAME = "KSeF CertVerify"
PRODUCT_SUBTITLE = "Weryfikacja certyfikatów KSeF"
PRODUCT_DESCRIPTION = "Weryfikacja certyfikatów KSeF – offline i online"
# Stały adres repozytorium (zgodny z [project.urls] w pyproject.toml; NIE jest odczytywany z lokalnego `git remote`).
REPOSITORY_URL = "https://github.com/zvgelo/KSeF-cert-verify"
PRODUCT_TAGLINE = f"{PRODUCT_NAME} – {PRODUCT_SUBTITLE}"
CLI_COMMAND = "ksef-cert-verify"
REPOSITORY_NAME = "KSeF-cert-verify"
LICENSE_NAME = "MIT"
DISCLAIMER = (
    "Wynik lokalny nie oznacza aktywnego statusu certyfikatu w KSeF ani potwierdzenia zgodności przez "
    "Ministerstwo Finansów. MF nie publikuje CA certyfikatów KSeF – zaufane CA konfiguruje użytkownik."
)
