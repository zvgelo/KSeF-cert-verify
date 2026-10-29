#!/usr/bin/env bash
# Pakiety Linux z jednego payloadu PyInstaller (scripts/build.py).
#   packaging/linux/build.sh payload|appimage|deb|rpm|checksums|all
# Budowanie payloadu: najlepiej w środowisku ze starą glibc (CI: ubuntu-22.04, lokalnie: packaging/linux/container-build.sh).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"
VERSION="$($PY -c 'import sys; sys.path.insert(0,"src"); from ksef_cert_verify import __version__; print(__version__)')"
# RPM i DEB wymagają numeracji rosnącej według ich porównań; dopuszczamy tylko liczby rozdzielone kropkami (np. 1.1.0).
[[ "$VERSION" =~ ^[0-9]+(\.[0-9]+)*$ ]] || { echo "Nieobsługiwany format wersji: $VERSION (dozwolone: 1.2.3)" >&2; exit 1; }
# Minimalna glibc = glibc maszyny budującej (payload PyInstaller linkuje się z jej bibliotekami systemowymi).
GLIBC_MIN="${GLIBC_MIN:-}"
[ -z "$GLIBC_MIN" ] && [ -f "$ROOT/dist/GLIBC_MIN" ] && GLIBC_MIN="$(cat "$ROOT/dist/GLIBC_MIN")"
[ -z "$GLIBC_MIN" ] && GLIBC_MIN="$(ldd --version 2>&1 | sed -n '1s/.* //p')"
PAYLOAD="$ROOT/dist/ksef-cert-verify"
ASSETS="$ROOT/packaging/assets"
OUT="$ROOT/dist"
mkdir -p "$OUT"

payload() { "$PY" scripts/build.py; ldd --version 2>&1 | sed -n '1s/.* //p' > "$ROOT/dist/GLIBC_MIN"; }

need_payload() { [ -x "$PAYLOAD/ksef-cert-verify" ] || { echo "Brak payloadu: uruchom '$0 payload'" >&2; exit 1; }; }

appimage() {
  need_payload
  local tool="${APPIMAGETOOL:-}"
  [ -n "$tool" ] && [ -x "$tool" ] || { echo "Ustaw APPIMAGETOOL na ścieżkę do appimagetool-x86_64.AppImage (pobierz z https://github.com/AppImage/appimagetool/releases i zweryfikuj)" >&2; exit 1; }
  local AD="$ROOT/build/AppDir"
  rm -rf "$AD"
  mkdir -p "$AD/usr/lib" "$AD/usr/share/applications" "$AD/usr/share/icons/hicolor/256x256/apps"
  cp -a "$PAYLOAD" "$AD/usr/lib/ksef-cert-verify"
  install -m755 packaging/linux/appimage/AppRun "$AD/AppRun"
  install -m644 "$ASSETS/ksef-cert-verify.desktop" "$AD/ksef-cert-verify.desktop"
  install -m644 "$ASSETS/ksef-cert-verify.desktop" "$AD/usr/share/applications/ksef-cert-verify.desktop"
  install -m644 "$ASSETS/icon.png" "$AD/ksef-cert-verify.png"
  install -m644 "$ASSETS/icon.png" "$AD/usr/share/icons/hicolor/256x256/apps/ksef-cert-verify.png"
  ln -sf ksef-cert-verify.png "$AD/.DirIcon"
  ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$tool" --no-appstream "$AD" "$OUT/KSeF-cert-verify-$VERSION-linux-x86_64.AppImage"
}

deb() {
  need_payload
  command -v dpkg-deb >/dev/null || { echo "Brak dpkg-deb (buduj na Debian/Ubuntu)" >&2; exit 1; }
  local R="$ROOT/build/deb/ksef-cert-verify_${VERSION}_amd64"
  rm -rf "$R"
  mkdir -p "$R/DEBIAN" "$R/opt" "$R/usr/bin" "$R/usr/share/applications" "$R/usr/share/doc/ksef-cert-verify"
  cp -a "$PAYLOAD" "$R/opt/ksef-cert-verify"
  ln -s ../../opt/ksef-cert-verify/ksef-cert-verify "$R/usr/bin/ksef-cert-verify"
  ln -s ../../opt/ksef-cert-verify/ksef-cert-verify-gui "$R/usr/bin/ksef-cert-verify-gui"
  install -m644 "$ASSETS/ksef-cert-verify.desktop" "$R/usr/share/applications/ksef-cert-verify.desktop"
  for s in 16 32 48 64 128 256; do
    install -Dm644 "$ASSETS/icon-$s.png" "$R/usr/share/icons/hicolor/${s}x${s}/apps/ksef-cert-verify.png"
  done
  install -Dm644 "$ASSETS/icon.svg" "$R/usr/share/icons/hicolor/scalable/apps/ksef-cert-verify.svg"
  install -m644 LICENSE "$R/usr/share/doc/ksef-cert-verify/copyright"
  install -m644 README.md "$R/usr/share/doc/ksef-cert-verify/README.md"
  local size; size="$(du -sk "$R" | cut -f1)"
  sed -e "s/@VERSION@/$VERSION/" -e "s/@SIZE@/$size/" -e "s/@GLIBC@/$GLIBC_MIN/" packaging/linux/deb/control.in > "$R/DEBIAN/control"
  install -m755 packaging/linux/deb/postinst "$R/DEBIAN/postinst"
  install -m755 packaging/linux/deb/postrm "$R/DEBIAN/postrm"
  find "$R" -type d -exec chmod 755 {} +
  dpkg-deb --root-owner-group -Zxz --build "$R" "$OUT/ksef-cert-verify_${VERSION}_amd64.deb"
}

rpm() {
  need_payload
  command -v rpmbuild >/dev/null || { echo "Brak rpmbuild (dnf install rpm-build)" >&2; exit 1; }
  local top="$ROOT/build/rpm"
  rm -rf "$top"
  mkdir -p "$top"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
  rpmbuild -bb packaging/linux/rpm/ksef-cert-verify.spec --define "_topdir $top" \
    --define "pkg_version $VERSION" --define "glibc_min $GLIBC_MIN" --define "payload $PAYLOAD" --define "assets $ASSETS"
  cp "$top"/RPMS/x86_64/ksef-cert-verify-"$VERSION"-1.x86_64.rpm "$OUT/"
}

checksums() {
  ( cd "$OUT" && : > SHA256SUMS && for f in *.AppImage *.rpm *.deb *-setup.exe; do [ -f "$f" ] && sha256sum "$f" >> SHA256SUMS; done; cat SHA256SUMS )
}

case "${1:-all}" in
  payload) payload ;;
  appimage) appimage ;;
  deb) deb ;;
  rpm) rpm ;;
  checksums) checksums ;;
  all) payload; appimage; deb; rpm; checksums ;;
  *) echo "Użycie: $0 payload|appimage|deb|rpm|checksums|all" >&2; exit 2 ;;
esac
