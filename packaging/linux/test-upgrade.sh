#!/usr/bin/env bash
# Test aktualizacji pakietu natywnym menedżerem: starsza wersja → nowsza (DWA PRAWDZIWE pakiety), potem odinstalowanie.
#   packaging/linux/test-upgrade.sh <stary.rpm|deb> <nowy.rpm|deb>      (uruchamiać jako root, najlepiej w kontenerze)
set -euo pipefail
OLD="$(readlink -f "$1")"; NEW="$(readlink -f "$2")"
case "$NEW" in *.rpm) KIND=rpm ;; *.deb) KIND=deb ;; *) echo "Nieznany typ pakietu" >&2; exit 2 ;; esac
PKG=ksef-cert-verify
fail=0
ok() { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; fail=$((fail + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

pkg_version() { if [ "$KIND" = rpm ]; then rpm -qp --qf '%{VERSION}' "$1"; else dpkg-deb -f "$1" Version; fi; }
pkg_files() { if [ "$KIND" = rpm ]; then rpm -qlp "$1"; else dpkg-deb -c "$1" | awk '{print $6}' | sed 's|^\./|/|;s|/$||'; fi | sort -u; }
installed_count() { if [ "$KIND" = rpm ]; then rpm -q "$PKG" | wc -l; else dpkg -l "$PKG" | grep -c '^ii'; fi; }
install_pkg() {
  if [ "$KIND" = rpm ]; then dnf install -y "$1" >/dev/null; else apt-get install -y "$1" >/dev/null; fi
}
upgrade_pkg() {
  if [ "$KIND" = rpm ]; then dnf upgrade -y "$1" >/dev/null; else apt-get install -y "$1" >/dev/null; fi
}

OLD_V="$(pkg_version "$OLD")"; NEW_V="$(pkg_version "$NEW")"
echo "Aktualizacja $PKG: $OLD_V → $NEW_V ($KIND)"
[ "$OLD_V" != "$NEW_V" ] || { echo "FAIL: pakiety mają tę samą wersję – to nie jest test aktualizacji"; exit 1; }
[ -x /opt/ksef-cert-verify/ksef-cert-verify ] && { echo "FAIL: pakiet jest już zainstalowany"; exit 1; }

install_pkg "$OLD"
check "stara wersja: CLI --version = $OLD_V" '[ "$(ksef-cert-verify --version)" = "ksef-cert-verify $OLD_V" ]'
# konfiguracja użytkownika (QSettings) i plik, który nie należy do pakietu – muszą przetrwać aktualizację
HOME_DIR="${HOME:-/root}"
mkdir -p "$HOME_DIR/.config/KSeF-cert-verify"
printf '[General]\ntheme=dark\n' > "$HOME_DIR/.config/KSeF-cert-verify/KSeF CertVerify.conf"

upgrade_pkg "$NEW"
check "po aktualizacji: CLI --version = $NEW_V" '[ "$(ksef-cert-verify --version)" = "ksef-cert-verify $NEW_V" ]'
check "po aktualizacji: GUI --selftest" 'QT_QPA_PLATFORM=offscreen ksef-cert-verify-gui --selftest >/dev/null 2>&1'
check "zainstalowany dokładnie jeden pakiet" '[ "$(installed_count)" = 1 ]'
check "wpis menu: dokładnie jeden plik .desktop" '[ "$(ls /usr/share/applications | grep -c ksef-cert-verify)" = 1 ]'
check "konfiguracja użytkownika zachowana" 'grep -q "theme=dark" "$HOME_DIR/.config/KSeF-cert-verify/KSeF CertVerify.conf"'

# pliki, które były w starym pakiecie, a nie ma ich w nowym, nie mogą zostać na dysku
removed="$(comm -23 <(pkg_files "$OLD") <(pkg_files "$NEW") | grep -v '/$' || true)"
leftover=0
while IFS= read -r f; do [ -n "$f" ] && [ -e "$f" ] && { echo "  pozostałość: $f"; leftover=$((leftover + 1)); }; done <<< "$removed"
check "brak plików z poprzedniej wersji (usuniętych w nowej: $(printf '%s\n' "$removed" | grep -c . || true))" '[ "$leftover" = 0 ]'

# działa pełna weryfikacja na zainstalowanej wersji (dane syntetyczne)
if [ -n "${FIXTURES:-}" ]; then
  out="$(ksef-cert-verify verify --cert "$FIXTURES/KSeF_Ksiegowosc.crt" --key "$FIXTURES/KSeF_Ksiegowosc.key" -t "$FIXTURES/ca.pem" --password-stdin --json < "$FIXTURES/password.txt" || true)"
  check "CERT + KEY + PASSWORD po aktualizacji: VALID" 'echo "$out" | grep -q "\"result\": \"VALID\""'
fi

if [ "$KIND" = rpm ]; then dnf remove -y "$PKG" >/dev/null; else apt-get remove -y "$PKG" >/dev/null; fi
check "odinstalowanie: brak katalogu /opt/ksef-cert-verify" '[ ! -e /opt/ksef-cert-verify ]'
check "odinstalowanie: brak poleceń w /usr/bin" '[ ! -e /usr/bin/ksef-cert-verify ] && [ ! -e /usr/bin/ksef-cert-verify-gui ]'
check "odinstalowanie: brak wpisu menu" '[ ! -e /usr/share/applications/ksef-cert-verify.desktop ]'
check "odinstalowanie: konfiguracja użytkownika nietknięta" '[ -f "$HOME_DIR/.config/KSeF-cert-verify/KSeF CertVerify.conf" ]'
rm -rf "$HOME_DIR/.config/KSeF-cert-verify"
[ "$fail" = 0 ] && echo "WSZYSTKIE TESTY AKTUALIZACJI ZALICZONE" || { echo "BŁĘDY: $fail"; exit 1; }
