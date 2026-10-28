# Ustalenia techniczne (Etap 1 – research)

Źródła analizowane 2026-10-28: `CIRFMF/ksef-api` i `CIRFMF/ksef-docs` (`certyfikaty-KSeF.md` z 03.02.2026,
`uwierzytelnianie.md`, `kody-qr.md`, `api-changelog.md`, `open-api.json` v2.9.0, `srodowiska.md`,
`auth/podpis-xades.md`, `bezpieczenstwo/klucze-publiczne-do-szyfrowania.md`), a także `ksef-client-csharp`
i `ksef-client-java` oraz opublikowane pliki OpenAPI środowisk TEST/DEMO/PROD.

## 1. Co dokumentacja MF **określa**

| Ustalenie | Źródło |
|---|---|
| Dwa typy certyfikatów KSeF: `Authentication`, `Offline`; certyfikat ma **tylko jeden** typ. | `certyfikaty-KSeF.md`, „Wstęp" |
| `Authentication` → keyUsage **Digital Signature (80)**. | tamże, tabela typów |
| `Offline` → keyUsage **Non-Repudiation (40)**; służy do podpisu KODU II, nie umożliwia uwierzytelnienia. | tamże; `kody-qr.md` §2 |
| Certyfikat KSeF **nie jest** kwalifikowany, nie przenosi uprawnień ani kontekstu; uprawnienia są po stronie KSeF. | `certyfikaty-KSeF.md`, `uwierzytelnianie.md` |
| Klucz: RSA 2048 bitów **lub** EC NIST P-256 (secp256r1); zalecane EC. (Dotyczy klucza w CSR – klucz trafia do wystawionego certyfikatu; zastosowanie do certyfikatu to wniosek z tego faktu.) | `certyfikaty-KSeF.md` §3 |
| Dozwolone atrybuty DN (8 OID): CN 2.5.4.3, surname 2.5.4.4, serialNumber 2.5.4.5, C 2.5.4.6, O 2.5.4.10, givenName 2.5.4.42, uniqueIdentifier 2.5.4.45, organizationIdentifier 2.5.4.97. Osoba: CN, surname, serialNumber, C, givenName, (uniqueIdentifier). Pieczęć: CN, C, O, organizationIdentifier, (uniqueIdentifier). | tamże §2 (tabela) |
| Wzorce identyfikatorów: `serialNumber` → `(PNOPL\|PESEL).*?(\d{11})`, `(TINPL\|NIP).*?(\d{10})`; `organizationIdentifier` → `(VATPL).*?(\d{10})`. | `auth/podpis-xades.md` |
| Identyfikacja odciskiem palca (SHA-256 certyfikatu) istnieje, gdy w certyfikacie brak PESEL/NIP. | `auth/podpis-xades.md`, `uprawnienia.md` |
| Numer seryjny w API: `^[0-9A-F]{16}$`. | `open-api.json` (`CertificateListItem`) |
| Status online (`POST /certificates/query`): `Active`, `Blocked`, `Revoked`, `Expired`; wymaga **Bearer JWT** (uwierzytelnienie XAdES / token), zwraca certyfikaty **uwierzytelnionego podmiotu**. | `open-api.json`, `certyfikaty-KSeF.md` §7 |
| Kontrakt zapytania: body `QueryCertificatesRequest` {certificateSerialNumber (exact), name, type, status, expiresAfter}; query `pageSize` 10–50, `pageOffset`. Odpowiedź `{certificates:[CertificateListItem], hasMore}`; pola: certificateSerialNumber, name, type, commonName, status, subjectIdentifier{type: Nip\|Pesel\|Fingerprint, value}, validFrom, validTo, lastUseDate, requestDate. Limity: 10/s, 30/min, 120/h; 429 + `Retry-After`. | `open-api.json` |
| Adresy API: TEST `https://api-test.ksef.mf.gov.pl/v2`, DEMO `https://api-demo.ksef.mf.gov.pl/v2`, PROD `https://api.ksef.mf.gov.pl/v2` (potwierdzone w opublikowanych OpenAPI każdego środowiska). | `srodowiska.md` + pobrane `openapi.json` |
| Certyfikat KSeF ważny maks. 2 lata (informacja urzędowa, nie z repozytorium API). | ksef.podatki.gov.pl/informacje-ogolne-ksef-20/certyfikaty-ksef/ |

## 2. Czego dokumentacja **nie określa** (ograniczenia)

1. **Brak opublikowanego CA / łańcucha zaufania** dla certyfikatów wewnętrznych KSeF. Brak URL do pobrania, brak odcisków.
   `GET /security/public-key-certificates` zwraca certyfikaty MF służące do **szyfrowania** (inny cel, inny wystawca) –
   **nie wolno** ich używać jako kotwic zaufania.
   → Kotwice zaufania (`--trust-anchor`, katalog zaufania) **dostarcza użytkownik**. Bez kotwic zaufanie = `NOT_CHECKED`,
   wynik końcowy najwyżej `INDETERMINATE`.
2. **Brak OID-ów polityk certyfikatów, wymagań EKU, SAN, krytyczności Key Usage, CRL/OCSP** dla certyfikatów KSeF.
   → Brak EKU/polityk nie jest błędem; obecność EKU zgłaszana jest jako `WARNING` (dokumentacja milczy).
3. **Brak oficjalnych certyfikatów testowych KSeF.** Środowisko TEST dopuszcza certyfikaty self-signed – ale tylko jako
   substytut certyfikatów kwalifikowanych przy uwierzytelnieniu, nie jako certyfikaty KSeF.
   → Wszystkie fixtury w repozytorium są **symulowane** (znacznik `simulated`) i nie dowodzą zgodności z MF.
4. Nie ma publicznego, nieuwierzytelnionego endpointu statusu certyfikatu. Status online wymaga tokenu dostępu
   uzyskanego poza programem (XAdES); program **nie** implementuje przepływu uwierzytelnienia.
5. Mapowanie numeru seryjnego X.509 na 16-znakowy hex z API jest **wnioskiem**, nie udokumentowanym faktem (zapytanie
   o numer, którego format nie pasuje, zwraca `UNKNOWN`).
6. Brak informacji o limicie `pathLen`, nazwach CA i profilu certyfikatów CA.

## 3. Decyzje implementacyjne wynikające z ustaleń

- **Typ**: Key Usage dokładnie {digitalSignature} → Authentication; {contentCommitment} → Offline; oba bity → `FAIL`
  (dokumentacja: jeden typ); żaden z nich → `FAIL`; dodatkowe bity → `UNKNOWN`.
- **Klucz**: RSA = 2048, EC = secp256r1, inaczej `FAIL`.
- **Podpis certyfikatu**: MD5 → `FAIL`, SHA-1 → `WARNING`; wyłącznie RSA (PKCS#1 v1.5/PSS) i ECDSA.
- **Walidacja łańcucha**: własna, per-ogniwo (`verify_directly_issued_by` + BasicConstraints + keyCertSign + pathLen + daty);
  kotwica to **identyczny DER** skonfigurowanego certyfikatu – nigdy dopasowanie po tekście Subject/Issuer. Certyfikaty z
  analizowanego pliku są co najwyżej kandydatami na pośrednie, nigdy kotwicami. Profil „web PKI" z
  `cryptography.x509.verification` nie jest używany (wymaga SAN/EKU, których certyfikaty KSeF nie muszą mieć).
- **Nieznane rozszerzenie krytyczne** → `FAIL`. `CA=true` w certyfikacie końcowym → `FAIL`.
- **Ważność > 2 lata** → `WARNING`; **serial ≠ 16 hex** → `WARNING`.
- **Status online** `Active` ≠ „VALID offline”; wynik offline nigdy nie oznacza aktywnego statusu w KSeF.
- Pusta odpowiedź `/certificates/query` = „nie znaleziono dla uwierzytelnionego podmiotu” → `UNKNOWN`, nie `Revoked`.

## 4. Dodatkowe decyzje (po Etapie 1)

- **Krytyczne NameConstraints / PolicyConstraints** w certyfikacie CA/liścia → `FAIL` (fail-closed): program ich nie egzekwuje,
  więc nie może ich uznać za „znane”.
- **Numer seryjny** jest wyświetlany jako hex dopełniony do 16 znaków (format z API: `^[0-9A-F]{16}$`). To **wniosek** (mapowanie
  serial X.509 → pole API nie jest udokumentowane); zapytanie online używa tej samej postaci.
- **Para certyfikat + klucz prywatny** (wymaganie projektowe, nie wymóg MF): `VALID` tylko po odszyfrowaniu klucza i zgodności SPKI.
  Dokumentacja MF opisuje klucz prywatny jedynie jako „przechowywany bezpiecznie” (`certyfikaty-KSeF.md` §3) – format pliku klucza
  (PKCS#8 / tradycyjny PEM) nie jest narzucony, więc obsługujemy oba oraz DER.
- Ścieżka **MD5 → FAIL** w sprawdzaniu podpisu nie ma testu (OpenSSL nie podpisuje MD5); SHA-1 → `WARNING` testowany tylko, jeśli
  OpenSSL pozwala.

## 5. Uwierzytelnianie, KOD II i CA (analiza dla rozszerzeń)

- **CA/łańcuch:** ponowna analiza `certyfikaty-KSeF.md`, `uwierzytelnianie.md`, `open-api.json` i bibliotek MF nie wykazała żadnego
  endpointu ani dokumentu z certyfikatami CA wystawiającymi certyfikaty KSeF (`/certificates/retrieve` zwraca tylko certyfikaty własne
  uwierzytelnionego podmiotu; `/security/public-key-certificates` to klucze szyfrujące MF). Dlatego CA nie są pobierane automatycznie –
  są zarządzane przez użytkownika z potwierdzeniem odcisku. Dokumentacja wspomina, że w KSeF weryfikacja certyfikatu KSeF odbywa się
  „wewnątrz systemu” (bez OCSP/CRL), więc status online jest właściwym źródłem statusu.
- **Uwierzytelnianie XAdES:** `POST /auth/challenge` → `AuthTokenRequest` (ns `http://ksef.mf.gov.pl/auth/token/2.0`, zgodny z żywym
  `authv2.xsd`) → `POST /auth/xades-signature` (202) → `GET /auth/{ref}` (Bearer `authenticationToken`; 100 w toku, 200 sukces, 415 brak
  uprawnień, 460 błąd certyfikatu, 450/425/470/480 inne) → `POST /auth/token/redeem` (jednorazowo, `accessToken`+`refreshToken`).
  Struktura podpisu odwzorowuje `SignatureService.cs` z `ksef-client-csharp` (C14N 1.0 dla `SignedInfo`, referencja `URI=""` z transformatami
  enveloped + exc-c14n, referencja do `#SignedProperties`, `SigningCertificate/IssuerSerial`). RSA: PKCS#1 v1.5/SHA-256; EC: ECDSA/SHA-256 w formacie R||S.
- **Niezweryfikowane wobec serwera:** wygenerowany XAdES został sprawdzony niezależną biblioteką `signxml` (RSA i EC), ale **nie** wysłany do
  prawdziwego API KSeF (brak poświadczeń i zgody na wywołania sieciowe w trakcie prac). Zgodność z serwerem wymaga kontrolowanego testu na środowisku TEST.
- **Znaleziony błąd w trakcie prac:** `lxml` przy kanonikalizacji poddrzewa nie dopisuje odziedziczonych `xmlns` – podpis liczony z takiej postaci
  nie zgadzałby się z weryfikatorem. Kanonikalizujemy samodzielną kopię elementu. libxml2 przy c14n 1.0 dopisuje też fałszywe `xmlns=""`
  (zob. signxml #193), stąd w teście niezależnej weryfikacji opcja `excise_empty_xmlns_declarations`.
- **KOD II:** format i algorytmy wg `kody-qr.md` §2 (RSASSA-PSS SHA-256/MGF1/sól 32 B, ECDSA P-256 SHA-256 w P1363, Base64URL bez dopełnienia,
  podpisywana ścieżka bez `https://` i bez końcowego `/`). Hosty QR: `qr-test`, `qr-demo`, `qr`. Podpis jest tylko liczony i weryfikowany lokalnie.
- **Dopasowanie statusu online:** serwer filtruje po numerze seryjnym (dokładne dopasowanie), ale program dodatkowo porównuje typ, `validFrom`/`validTo`
  (±2 s), `commonName` i identyfikator (NIP/PESEL); niezgodność daje `UNKNOWN`, nie `Active`.
