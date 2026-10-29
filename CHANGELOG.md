# Changelog

## 1.0.1

- GUI: simpler verification, certificate owner details.
- Certificate verification fixes.
- KOD II verification per MF specification.
- Installer upgrade handling.

## 1.0.0

Pierwsze wydanie.

- Weryfikacja certyfikatu KSeF razem z zaszyfrowanym kluczem prywatnym i hasłem (RSA 2048, EC P-256), aktywny test podpisu.
- Rozdzielone wyniki: LOCAL (zestaw cert+klucz), TRUST (łańcuch, CA, profil KSeF), ONLINE (status, uwierzytelnienie).
- Test podpisu KODU II (certyfikat Offline), test uwierzytelnienia XAdES (certyfikat Authentication) – dotąd sprawdzone wyłącznie na mockowanym API.
- Status certyfikatu w API KSeF (`POST /certificates/query`).
- CLI (`ksef-cert-verify`) i GUI PySide6 (KSeF CertVerify), motywy jasny/ciemny.
- Windows: Setup (Inno Setup), Portable (jeden plik GUI) i samodzielne CLI (jeden plik); Linux: AppImage, RPM, DEB.
