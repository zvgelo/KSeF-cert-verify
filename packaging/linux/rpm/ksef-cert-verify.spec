# Spec pakujący GOTOWY payload PyInstaller (patrz scripts/build.py) – nie buduje ze źródeł.
# rpmbuild -bb --define "pkg_version 1.0.0" --define "payload /ścieżka/dist/ksef-cert-verify" \
#        --define "assets /ścieżka/packaging/assets" ksef-cert-verify.spec
%global debug_package %{nil}
%global __strip /bin/true
%global __os_install_post %{nil}
%global _build_id_links none
AutoReqProv: no

Name:           ksef-cert-verify
Version:        %{pkg_version}
Release:        1
Summary:        KSeF CertVerify – Weryfikacja certyfikatów KSeF (CLI i GUI)
License:        MIT
BuildArch:      x86_64
Requires:       glibc >= %{glibc_min}
Requires:       mesa-libEGL, mesa-libGL, libxkbcommon, libxkbcommon-x11, xcb-util-cursor
Requires:       xcb-util-image, xcb-util-keysyms, xcb-util-renderutil, xcb-util-wm, libxcb
Requires:       fontconfig, dbus-libs, glib2
Requires(post): desktop-file-utils
Requires(postun): desktop-file-utils

%description
KSeF CertVerify – Weryfikacja certyfikatów KSeF. Sprawdza certyfikat KSeF (Authentication / Offline) razem z zaszyfrowanym kluczem prywatnym:
daty, łańcuch zaufania (CA podane przez użytkownika), profil KSeF oraz zgodność pary kluczy.
Działa offline. Wynik lokalny nie oznacza aktywnego statusu certyfikatu w KSeF.

%prep
%build

%install
rm -rf %{buildroot}
install -d %{buildroot}/opt/ksef-cert-verify %{buildroot}%{_bindir}
cp -a %{payload}/. %{buildroot}/opt/ksef-cert-verify/
ln -s ../../opt/ksef-cert-verify/ksef-cert-verify %{buildroot}%{_bindir}/ksef-cert-verify
ln -s ../../opt/ksef-cert-verify/ksef-cert-verify-gui %{buildroot}%{_bindir}/ksef-cert-verify-gui
install -Dm644 %{assets}/ksef-cert-verify.desktop %{buildroot}%{_datadir}/applications/ksef-cert-verify.desktop
for s in 16 32 48 64 128 256; do
  install -Dm644 %{assets}/icon-$s.png %{buildroot}%{_datadir}/icons/hicolor/${s}x${s}/apps/ksef-cert-verify.png
done
install -Dm644 %{assets}/icon.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/ksef-cert-verify.svg

%post
update-desktop-database -q %{_datadir}/applications &>/dev/null || :
gtk-update-icon-cache -q -t %{_datadir}/icons/hicolor &>/dev/null || :

%postun
update-desktop-database -q %{_datadir}/applications &>/dev/null || :
gtk-update-icon-cache -q -t %{_datadir}/icons/hicolor &>/dev/null || :

%files
/opt/ksef-cert-verify
%{_bindir}/ksef-cert-verify
%{_bindir}/ksef-cert-verify-gui
%{_datadir}/applications/ksef-cert-verify.desktop
%{_datadir}/icons/hicolor/*/apps/ksef-cert-verify.*

%changelog
* Wed Oct 28 2026 KSeF-cert-verify contributors - %{version}-1
- Wydanie %{version}
