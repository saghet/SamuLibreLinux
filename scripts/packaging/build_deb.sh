#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SamuLibre - Generador de Paquete .deb para Ubuntu / Debian
# Soporta Ubuntu 22.04 LTS, 24.04 LTS y Debian 12
# ==============================================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
ARCH="amd64"
PKG_DIR="target/debian/samulibre_${VERSION}_${ARCH}"

echo "==> [Ubuntu/Debian] Compilando binarios de SamuLibre ${VERSION} en release..."
cargo build --release -p samulibre-gui -p samulibre-cli

echo "==> [Ubuntu/Debian] Preparando árbol de directorios de empaquetado..."
rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/usr/bin"
mkdir -p "${PKG_DIR}/usr/share/applications"
mkdir -p "${PKG_DIR}/usr/share/pixmaps"
mkdir -p "${PKG_DIR}/usr/lib/systemd/user"

echo "==> [Ubuntu/Debian] Copiando binarios y accesos de escritorio..."
cp target/release/samulibre-gui "${PKG_DIR}/usr/bin/samulibre-gui"
cp target/release/samulibre-cli "${PKG_DIR}/usr/bin/samulibre-cli"
ln -sf samulibre-cli "${PKG_DIR}/usr/bin/samulibre"
chmod 755 "${PKG_DIR}/usr/bin/samulibre-gui" "${PKG_DIR}/usr/bin/samulibre-cli"

cp data/samulibre.desktop "${PKG_DIR}/usr/share/applications/samulibre.desktop"
cp data/samulibre.desktop "${PKG_DIR}/usr/share/applications/org.samulibre.samulibre.desktop"
cp data/samulibre.service "${PKG_DIR}/usr/lib/systemd/user/samulibre.service"

# Multi-resolución de iconos y SVG escalable
echo "==> [Ubuntu/Debian] Generando e instalando iconos multirresolución Freedesktop..."
for size in 16x16 22x22 24x24 32x32 48x48 64x64 128x128 256x256 512x512; do
    target_dir="${PKG_DIR}/usr/share/icons/hicolor/${size}/apps"
    mkdir -p "${target_dir}"
    if command -v magick >/dev/null 2>&1; then
        magick assets/icon.png -resize "${size}" "${target_dir}/samulibre.png"
    else
        cp assets/icon.png "${target_dir}/samulibre.png"
    fi
    cp "${target_dir}/samulibre.png" "${target_dir}/org.samulibre.samulibre.png"
done

mkdir -p "${PKG_DIR}/usr/share/icons/hicolor/scalable/apps"
cp assets/icon.svg "${PKG_DIR}/usr/share/icons/hicolor/scalable/apps/samulibre.svg"
cp assets/icon.svg "${PKG_DIR}/usr/share/icons/hicolor/scalable/apps/org.samulibre.samulibre.svg"

cp assets/icon.png "${PKG_DIR}/usr/share/pixmaps/samulibre.png"
cp assets/icon.png "${PKG_DIR}/usr/share/pixmaps/org.samulibre.samulibre.png"

# Recursos completos (UI, firmas, catálogo KB, reglas CVE, sandbox, canarios)
bash scripts/packaging/stage_data.sh "${PKG_DIR}/usr/share/samulibre/data"

echo "==> [Ubuntu/Debian] Generando metadatos DEBIAN/control..."
cat << EOF > "${PKG_DIR}/DEBIAN/control"
Package: samulibre
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: amd64
Maintainer: SamuLibre Security Team <security@samulibre.org>
Depends: libc6 (>= 2.31), libwebkit2gtk-4.1-0, libgtk-3-0, tor, iptables, zenity
Recommends: apparmor, libayatana-appindicator3-1
Description: Suite de Seguridad y Antivirus Open Source para Linux
 SamuLibre es una solución integral de ciberdefensa ligera y modular para Linux:
  - Antivirus multipatrón heurístico, análisis YARA y detección por IA.
  - EDR con canarios anti-ransomware, autoprotección y protección de credenciales.
  - Parches Virtuales en memoria y mitigaciones sysctl del kernel.
  - Protección de navegadores y auditoría de extensiones.
  - VPN Tor integrada con doble cifrado y Kill-Switch.
EOF

cat << 'EOF' > "${PKG_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    update-desktop-database -q /usr/share/applications || true
    gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

cat << 'EOF' > "${PKG_DIR}/DEBIAN/prerm"
#!/bin/sh
set -e
pkill -f samulibre-gui || true
exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/prerm"

echo "==> [Ubuntu/Debian] Construyendo paquete .deb..."
mkdir -p target
if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb --build --root-owner-group "${PKG_DIR}" "target/samulibre_${VERSION}_${ARCH}.deb"
else
    echo "ℹ Utilizando empaquetador nativo Freedesktop GNU ar / tar (100% compatible con apt/dpkg)..."
    BUILD_DEB_DIR="$(mktemp -d)"
    echo "2.0" > "${BUILD_DEB_DIR}/debian-binary"
    tar -czf "${BUILD_DEB_DIR}/control.tar.gz" --owner=0 --group=0 -C "${PKG_DIR}/DEBIAN" .
    tar -czf "${BUILD_DEB_DIR}/data.tar.gz" --owner=0 --group=0 --exclude="./DEBIAN" -C "${PKG_DIR}" .
    ar -rcsD "target/samulibre_${VERSION}_${ARCH}.deb" "${BUILD_DEB_DIR}/debian-binary" "${BUILD_DEB_DIR}/control.tar.gz" "${BUILD_DEB_DIR}/data.tar.gz"
    rm -rf "${BUILD_DEB_DIR}"
fi

echo "✔ Paquete .deb para Ubuntu/Debian generado con éxito en: target/samulibre_${VERSION}_${ARCH}.deb"
