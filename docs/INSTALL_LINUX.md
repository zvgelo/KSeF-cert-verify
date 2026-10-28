# Instalacja – Linux

Administrator **nie** jest potrzebny dla AppImage ani pip (RPM/DEB instaluje się systemowo).

## AppImage (przenośny, bez instalacji)

```bash
chmod +x KSeF-cert-verify-<wersja>-linux-x86_64.AppImage
./KSeF-cert-verify-<wersja>-linux-x86_64.AppImage                 # GUI
./KSeF-cert-verify-<wersja>-linux-x86_64.AppImage --version        # z argumentami: CLI
./KSeF-cert-verify-<wersja>-linux-x86_64.AppImage verify --cert c.crt --key c.key -t ca.pem
```

Zawiera Pythona i PySide6, działa offline i niezależnie od katalogu roboczego. **Nie jest niezależny od bibliotek
systemowych**: wymaga glibc oraz bibliotek graficznych (patrz „Rozwiązywanie problemów”). Bez FUSE: `APPIMAGE_EXTRACT_AND_RUN=1`.
Aktualizacja = pobranie nowego pliku; usunięcie = skasowanie pliku (nic nie jest instalowane w systemie).

## Fedora – RPM

```bash
sudo dnf install ./ksef-cert-verify-<wersja>-1.x86_64.rpm      # instalacja lub aktualizacja (dnf upgrade ./nowy.rpm)
ksef-cert-verify --version
sudo dnf remove ksef-cert-verify                                # odinstalowanie
```

## Debian / Ubuntu – DEB

```bash
sudo apt install ./ksef-cert-verify_<wersja>_amd64.deb         # instalacja lub aktualizacja
ksef-cert-verify --version
sudo apt remove ksef-cert-verify                                # odinstalowanie
```

Pakiety instalują: `/opt/ksef-cert-verify/` (aplikacja), polecenia `ksef-cert-verify` i `ksef-cert-verify-gui` w `/usr/bin`,
wpis w menu (`.desktop`) i ikony. Nie ingerują w systemowego Pythona i nie instalują usług systemd.

## pip (CLI + GUI z kodu źródłowego)

Python 3.11+.

```bash
python3 -m venv ~/.venvs/ksef && source ~/.venvs/ksef/bin/activate
pip install ".[gui]"            # z katalogu repozytorium; samo CLI: pip install .
pip install --upgrade ".[gui]"  # aktualizacja
ksef-cert-verify gui
```

## Zaufane CA

```bash
mkdir -p ~/.config/ksef-cert-verify/trust && cp moje-ca.pem ~/.config/ksef-cert-verify/trust/
```

MF nie publikuje CA certyfikatów KSeF – patrz [CERTIFICATE_VALIDATION.md](CERTIFICATE_VALIDATION.md).

## Rozwiązywanie problemów z Qt i bibliotekami

| Objaw | Przyczyna / rozwiązanie |
|---|---|
| `Could not load the Qt platform plugin "xcb"` / `xcb-cursor0 ... not found` | brak `libxcb-cursor` – Ubuntu/Debian: `sudo apt install libxcb-cursor0`; Fedora: `sudo dnf install xcb-util-cursor` |
| `libEGL.so.1`, `libGL.so.1`, `libxkbcommon.so.0` not found | Ubuntu/Debian: `sudo apt install libegl1 libgl1 libxkbcommon0 libxkbcommon-x11-0`; Fedora: `sudo dnf install mesa-libEGL mesa-libGL libxkbcommon libxkbcommon-x11` |
| `libfontconfig`, `libdbus-1`, `libglib` not found | `libfontconfig1 libdbus-1-3 libglib2.0-0` (Debian/Ubuntu) / `fontconfig dbus-libs glib2` (Fedora) |
| `GLIBC_2.xx not found` | pakiet zbudowano na nowszym systemie niż Twój – użyj pakietu z wydania (budowanego na starszej glibc) lub zbuduj własny (niżej) |
| AppImage: `dlopen(): error loading libfuse.so.2` | `sudo apt install libfuse2` / `sudo dnf install fuse-libs`, albo `APPIMAGE_EXTRACT_AND_RUN=1 ./plik.AppImage` |
| brak ekranu (SSH, serwer) | `QT_QPA_PLATFORM=offscreen` (CLI działa bez Qt; GUI wymaga ekranu lub offscreen) |
| Wayland: okno bez dekoracji | `QT_QPA_PLATFORM=xcb ksef-cert-verify gui` |

Diagnoza: `ksef-cert-verify gui --selftest` (wynik `SELFTEST OK` = Qt i silnik działają).

## Budowanie własnych pakietów

Zob. [PACKAGING.md](PACKAGING.md): `scripts/build.py` (payload PyInstaller), `packaging/linux/build.sh rpm|deb|appimage`.
