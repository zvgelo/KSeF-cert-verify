#!/usr/bin/env bash
# Test E2E instalacji w kontenerze/VM:  test-install.sh <deb|rpm|appimage> <plik> <katalog-z-parą-syntetyczną>
# Wykonuje: instalacja → CLI (--version, pełna weryfikacja certyfikatu+klucza) → GUI --selftest → wpis menu →
# odinstalowanie → sprawdzenie usunięcia plików. Dane są syntetyczne (scripts/make_fixture_pair.py).
set -euo pipefail
KIND="$1"; FILE="$(readlink -f "$2")"; FIX="$(readlink -f "$3")"
export DEBIAN_FRONTEND=noninteractive QT_QPA_PLATFORM=offscreen
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

run_cli_tests() { # $1 = polecenie CLI
  local CLI="$1" rc
  "$CLI" --version | grep -q '^ksef-cert-verify ' && pass "CLI --version"
  set +e
  "$CLI" verify --cert "$FIX/KSeF_Ksiegowosc.crt" --key "$FIX/KSeF_Ksiegowosc.key" -t "$FIX/ca.pem" \
      --password-stdin --json < "$FIX/password.txt" > /tmp/out.json
  rc=$?; set -e
  if [ "$rc" -eq 0 ] && grep -q '"result": "VALID"' /tmp/out.json; then pass "CLI pełna weryfikacja (exit 0, VALID)"; else fail "CLI weryfikacja rc=$rc"; fi
  set +e
  echo "zle-haslo" | "$CLI" verify --cert "$FIX/KSeF_Ksiegowosc.crt" --key "$FIX/KSeF_Ksiegowosc.key" -t "$FIX/ca.pem" --password-stdin --json > /tmp/bad.json
  rc=$?; set -e
  if [ "$rc" -eq 1 ]; then pass "CLI błędne hasło → exit 1"; else fail "błędne hasło rc=$rc"; fi
}
run_gui_test() { # $1 = polecenie
  "$1" gui --selftest 2>&1 | tee /tmp/gui.log | tail -2
  if grep -q "SELFTEST OK" /tmp/gui.log; then pass "GUI --selftest (Qt offscreen)"; else fail "GUI selftest"; fi
}
no_leftovers() {
  if [ ! -e /opt/ksef-cert-verify ] && [ ! -e /usr/bin/ksef-cert-verify ] && [ ! -e /usr/bin/ksef-cert-verify-gui ] \
     && [ ! -e /usr/share/applications/ksef-cert-verify.desktop ]; then pass "pliki usunięte po odinstalowaniu"; else fail "pozostałości po odinstalowaniu"; fi
}
installed_checks() {
  command -v ksef-cert-verify >/dev/null && pass "ksef-cert-verify w PATH"
  [ -f /usr/share/applications/ksef-cert-verify.desktop ] && pass "wpis menu: .desktop zainstalowany"
  grep -q '^Name=KSeF CertVerify$' /usr/share/applications/ksef-cert-verify.desktop && pass "nazwa w menu: KSeF CertVerify"
  [ -f /opt/ksef-cert-verify/_internal/ksef_cert_verify/gui/assets/logo.svg ] && pass "zasoby GUI (logo, ikony) w pakiecie"
  [ -f /usr/share/icons/hicolor/256x256/apps/ksef-cert-verify.png ] && pass "ikona zainstalowana"
  [ -x /usr/bin/ksef-cert-verify-gui ] && pass "polecenie ksef-cert-verify-gui w PATH"
}

case "$KIND" in
  deb)
    apt-get update -qq
    apt-get install -y -qq "$FILE" >/dev/null && pass "apt install $(basename "$FILE")"
    installed_checks
    run_cli_tests ksef-cert-verify
    run_gui_test ksef-cert-verify
    apt-get install -y -qq desktop-file-utils >/dev/null
    desktop-file-validate /usr/share/applications/ksef-cert-verify.desktop && pass "desktop-file-validate"
    dpkg -s ksef-cert-verify | grep -q 'Status: install ok installed' && pass "dpkg status"
    apt-get remove -y -qq ksef-cert-verify >/dev/null && pass "apt remove"
    no_leftovers
    ;;
  rpm)
    dnf -y -q install "$FILE" >/dev/null && pass "dnf install $(basename "$FILE")"
    installed_checks
    run_cli_tests ksef-cert-verify
    run_gui_test ksef-cert-verify
    dnf -y -q install desktop-file-utils >/dev/null
    desktop-file-validate /usr/share/applications/ksef-cert-verify.desktop && pass "desktop-file-validate"
    rpm -q ksef-cert-verify >/dev/null && pass "rpm -q"
    dnf -y -q remove ksef-cert-verify >/dev/null && pass "dnf remove"
    no_leftovers
    ;;
  appimage)
    export APPIMAGE_EXTRACT_AND_RUN=1
    chmod +x "$FILE"
    run_cli_tests "$FILE"
    run_gui_test "$FILE"
    mkdir -p /tmp/other-cwd && cd /tmp/other-cwd && "$FILE" --version | grep -q ksef-cert-verify && pass "działa niezależnie od katalogu roboczego"
    ;;
  *) fail "nieznany rodzaj: $KIND" ;;
esac
echo "WSZYSTKIE TESTY ($KIND) ZALICZONE"
