# Walidacja certyfikatów

Pięć rzeczy, które program rozdziela (zob. README): **walidacja lokalna**, **zaufanie kryptograficzne**, **zgodność z KSeF**,
**status online**, **uprawnienia podmiotu**. Źródła reguł i ich ograniczenia: [TECHNICAL_FINDINGS.md](TECHNICAL_FINDINGS.md).

## Kontrole (każda: PASS / FAIL / WARNING / UNKNOWN / NOT_CHECKED)

| Kontrola | Co sprawdza | FAIL | UNKNOWN / NOT_CHECKED / WARNING |
|---|---|---|---|
| `parsing` | odczyt X.509 (ASN.1/DER) | (uszkodzony plik kończy się błędem pliku → `INVALID`) | – |
| `validity` | Not Before/Not After względem `now` | przed początkiem, po końcu, odwrócone daty | WARNING: ≤30 / ≤14 / ≤7 dni do końca; ważność > 2 lata |
| `crypto` | dozwolone algorytmy, **podpisy** w ścieżce | zły podpis, MD5, klucz spoza RSA/EC | UNKNOWN: brak certyfikatu wystawcy; WARNING: SHA-1 |
| `trust` | ścieżka kończy się w **skonfigurowanej** kotwicy; CA=TRUE, keyCertSign, pathLen, daty CA | niezaufany root, naruszone ograniczenia CA, podmiana CA | NOT_CHECKED: brak kotwic; UNKNOWN: brak ogniwa |
| `classification` | typ z Key Usage | brak obu bitów, oba bity, niezgodny `--expected-type` | UNKNOWN: brak KU albo dodatkowe bity |
| `profile` | udokumentowane kryteria MF (poniżej) | klucz ≠ RSA 2048 / P-256, CA=TRUE na liściu, nieznane rozszerzenie krytyczne | UNKNOWN: typ nieustalony; WARNING: EKU, nietypowy DN/serial |
| `key_decrypt` | odczyt klucza prywatnego (PEM/DER, PKCS#8 i tradycyjny RSA/EC), odszyfrowanie hasłem | błędne hasło / uszkodzony / nieobsługiwany format | UNKNOWN: brak hasła do zaszyfrowanego klucza; NOT_CHECKED: nie podano klucza; WARNING: klucz niezaszyfrowany |
| `key_match` | klucz publiczny wyprowadzony z klucza prywatnego == klucz w certyfikacie (SubjectPublicKeyInfo DER) | różne klucze (inny certyfikat, inny algorytm) | NOT_CHECKED: klucz nieodczytany |
| `online` | `POST /certificates/query` | Blocked / Revoked / Expired, niezgodny typ | NOT_CHECKED (domyślnie); UNKNOWN: brak uprawnień/wyniku/błąd sieci |

## Wynik końcowy

* `INVALID` – jakakolwiek obowiązkowa kontrola ma `FAIL`.
* `INDETERMINATE` – brak `FAIL`, ale któraś obowiązkowa kontrola to `UNKNOWN` / `NOT_CHECKED`.
* `VALID` – wszystkie obowiązkowe kontrole to `PASS` lub `WARNING`.

Obowiązkowe: `parsing, validity, crypto, trust, classification, profile, key_decrypt, key_match` (+ `online`, jeśli zażądano `--online`).
Bez klucza prywatnego i hasła wynik **nigdy** nie jest `VALID`.
`UNKNOWN` nigdy nie jest traktowane jak `PASS`. Ostrzeżenia nie unieważniają wyniku, ale są wyświetlane.

## Typ certyfikatu

Według `certyfikaty-KSeF.md`: `Authentication` ⇔ Key Usage = {Digital Signature}; `Offline` ⇔ {Non-Repudiation / Content Commitment}.
Typ nie jest odgadywany z nazwy pliku. Pojedynczy bit bez reszty profilu **nie** wystarcza do uznania certyfikatu za zgodny:
oceniają to `profile` i `trust`.

## Łańcuch zaufania

Własna walidacja per ogniwo (`verify_directly_issued_by` z biblioteki `cryptography`): podpis, zgodność nazw, CA=TRUE,
keyCertSign (jeśli KU obecne), `pathLen`, okres ważności CA, nieznane krytyczne rozszerzenia CA (w tym NameConstraints
i PolicyConstraints, których program **nie egzekwuje** – dlatego ich krytyczna obecność daje FAIL). Kotwica to **identyczny
DER** certyfikatu – samo `Subject` nie wystarcza (test „CA o identycznym Subject”). Certyfikaty z analizowanego pliku są co
najwyżej kandydatami na pośrednie. Nie jest używana walidacja „web PKI” (wymagałaby SAN/EKU, których certyfikaty KSeF nie muszą mieć).
Nie sprawdzamy CRL/OCSP (MF nie publikuje ich dla certyfikatów KSeF) – od tego jest status online.

## Skąd wziąć zaufane CA?

MF **nie publikuje** CA certyfikatów KSeF. Jeśli masz certyfikat CA z własnego, zweryfikowanego źródła (np. otrzymany od
MF/integratora, z odciskiem sprawdzonym drugim kanałem), umieść go w katalogu zaufania lub podaj `--trust-anchor`. Program
nie pobiera CA z internetu i **nie** używa certyfikatów z `/security/public-key-certificates` (to klucze szyfrujące MF – inny cel i wystawca).

## Subject i identyfikatory

Odczyt: CN, givenName, surname, O, C, serialNumber, organizationIdentifier, uniqueIdentifier. NIP/PESEL tylko ze wzorców
MF: `serialNumber` ~ `(PNOPL|PESEL)…\d{11}` / `(TINPL|NIP)…\d{10}`, `organizationIdentifier` ~ `VATPL…\d{10}` – i **tylko przy
poprawnej sumie kontrolnej**; w przeciwnym razie „Brak danych” (np. identyfikacja odciskiem palca). Nie zgadujemy NIP/PESEL z losowych cyfr.

## Czego program NIE potwierdza

* że MF uznaje certyfikat za wystawiony przez KSeF (brak oficjalnych CA/certyfikatów referencyjnych),
* że certyfikat jest aktywny, nieunieważniony ani że podmiot ma uprawnienia – to wyłącznie status online / model uprawnień KSeF,
* wymagań, których dokumentacja MF nie opisuje (EKU, polityki, krytyczność KU, limit `pathLen` CA KSeF).

## Para certyfikat + klucz prywatny

Porównanie jest wykonywane na reprezentacji kryptograficznej: z odszyfrowanego klucza prywatnego wyprowadzany jest klucz publiczny
i serializowany do **SubjectPublicKeyInfo DER**; to samo robimy dla klucza z certyfikatu; wynik to równość bajtów. Obsługiwane są
RSA i EC (klucz innego rodzaju niż w certyfikacie to niezgodność). Klucz prywatny nie opuszcza modułu `core/private_key.py` –
na zewnątrz wychodzi wyłącznie publiczny SPKI i status kontroli. Klucz zaszyfrowany pytamy o hasło dopiero, gdy jest potrzebne;
klucz niezaszyfrowany nie wymaga hasła i daje ostrzeżenie. Nie wykonujemy podpisu próbnego (porównanie SPKI jest wystarczające
dla pary klucz/certyfikat).

## Grupy wyników: LOCAL / TRUST / ONLINE

| Grupa | Kontrole | Wynik |
|---|---|---|
| LOCAL | `parsing`, `validity`, `inputs`, `key_decrypt`, `key_match`, `signature_test` | `VALID` / `INVALID` / `INDETERMINATE` |
| TRUST | `crypto`, `trust`, `classification`, `profile` | `CONFIRMED` / `UNCONFIRMED` / `FAILED` |
| ONLINE | `online` (+ uwierzytelnienie w `operations`) | `Active`… / `UNKNOWN` / `NOT_CHECKED` |

Wynik grupy to najgorszy status jej kontroli (`FAIL` > `UNKNOWN` > `NOT_CHECKED` > `WARNING` > `PASS`) – `UNKNOWN` nigdy nie staje się
`PASS`. Pełna walidacja (`VALID`) wymaga LOCAL = VALID **i** TRUST = CONFIRMED. Wyniki online nie wpływają na LOCAL ani TRUST.

## Aktywny test podpisu (`signature_test`)

32 losowe bajty (`secrets`), podpis kluczem prywatnym (RSA 2048: RSASSA-PSS/SHA-256/MGF1/sól 32; EC P-256: ECDSA/SHA-256),
weryfikacja kluczem publicznym z certyfikatu; referencje do klucza są zwalniane po teście (Python nie gwarantuje zerowania pamięci –
patrz SECURITY). Kody: `SIGNATURE_VALID`, `SIGNATURE_INVALID`, `KEY_DECRYPTION_FAILED`, `KEY_CERT_MISMATCH`, `UNSUPPORTED_ALGORITHM`.

## KOD II i uwierzytelnienie XAdES

Zob. [CLI.md](CLI.md) (`test-kod2`, `test-auth`). Podpis XAdES-BES odtwarza strukturę oficjalnej biblioteki MF (enveloped, C14N 1.0,
referencje do dokumentu i `SignedProperties`, certyfikat w `X509Data`); jest weryfikowany w testach **niezależną** biblioteką `signxml`.
**Nie został sprawdzony na prawdziwym serwerze KSeF** (patrz TECHNICAL_FINDINGS).
