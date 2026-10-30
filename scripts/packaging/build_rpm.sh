#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SamuLibre - Generador de Paquete .rpm para Red Hat Enterprise Linux / Fedora
# Compatible con RHEL 8/9/10, Rocky Linux, AlmaLinux y Fedora 39/40/41+
# ==============================================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
ARCH="x86_64"
RPM_NAME="samulibre-${VERSION}-1.${ARCH}.rpm"

echo "==> [Red Hat/Fedora] Compilando binarios de SamuLibre ${VERSION} en release..."
cargo build --release -p samulibre-gui -p samulibre-cli

echo "==> [Red Hat/Fedora] Preparando activos, datos y metadatos RPM..."
STAGE_DIR="${ROOT_DIR}/target/rpm_data"
rm -rf "${STAGE_DIR}"
bash scripts/packaging/stage_data.sh "${STAGE_DIR}"

ICONS_DIR="${ROOT_DIR}/target/icons"
mkdir -p "${ICONS_DIR}"
for size in 16x16 22x22 24x24 32x32 48x48 64x64 128x128 256x256 512x512; do
    if command -v magick >/dev/null 2>&1; then
        magick assets/icon.png -resize "${size}" "${ICONS_DIR}/samulibre_${size}.png"
    else
        cp assets/icon.png "${ICONS_DIR}/samulibre_${size}.png"
    fi
done

python3 -c "
import os

root_dir = '${ROOT_DIR}'
stage_dir = '${STAGE_DIR}'
icons_dir = '${ICONS_DIR}'

assets = [
    f'{{ source = \"{os.path.join(root_dir, \"target\", \"release\", \"samulibre-gui\")}\", dest = \"/usr/bin/samulibre-gui\", mode = \"755\" }}',
    f'{{ source = \"{os.path.join(root_dir, \"target\", \"release\", \"samulibre-cli\")}\", dest = \"/usr/bin/samulibre-cli\", mode = \"755\" }}',
    f'{{ source = \"{os.path.join(root_dir, \"data\", \"samulibre.desktop\")}\", dest = \"/usr/share/applications/samulibre.desktop\", mode = \"644\" }}',
    f'{{ source = \"{os.path.join(root_dir, \"data\", \"samulibre.desktop\")}\", dest = \"/usr/share/applications/org.samulibre.samulibre.desktop\", mode = \"644\" }}',
    f'{{ source = \"{os.path.join(root_dir, \"assets\", \"icon.svg\")}\", dest = \"/usr/share/icons/hicolor/scalable/apps/samulibre.svg\", mode = \"644\" }}',
    f'{{ source = \"{os.path.join(root_dir, \"assets\", \"icon.svg\")}\", dest = \"/usr/share/icons/hicolor/scalable/apps/org.samulibre.samulibre.svg\", mode = \"644\" }}',
    f'{{ source = \"{os.path.join(root_dir, \"assets\", \"icon.png\")}\", dest = \"/usr/share/pixmaps/samulibre.png\", mode = \"644\" }}',
    f'{{ source = \"{os.path.join(root_dir, \"assets\", \"icon.png\")}\", dest = \"/usr/share/pixmaps/org.samulibre.samulibre.png\", mode = \"644\" }}',
    f'{{ source = \"{os.path.join(root_dir, \"data\", \"samulibre.service\")}\", dest = \"/usr/lib/systemd/user/samulibre.service\", mode = \"644\" }}',
]

for size in ['16x16', '22x22', '24x24', '32x32', '48x48', '64x64', '128x128', '256x256', '512x512']:
    p = os.path.join(icons_dir, f'samulibre_{size}.png')
    assets.append(f'{{ source = \"{p}\", dest = \"/usr/share/icons/hicolor/{size}/apps/samulibre.png\", mode = \"644\" }}')
    assets.append(f'{{ source = \"{p}\", dest = \"/usr/share/icons/hicolor/{size}/apps/org.samulibre.samulibre.png\", mode = \"644\" }}')

for r, dirs, files in os.walk(stage_dir):
    for f in files:
        src = os.path.join(r, f)
        rel = os.path.relpath(src, stage_dir)
        dest = f'/usr/share/samulibre/data/{rel}'
        assets.append(f'{{ source = \"{src}\", dest = \"{dest}\", mode = \"644\" }}')

assets_str = ',\n  '.join(assets)

toml_content = f'''[package.metadata.generate-rpm]
name = \"samulibre\"
summary = \"Suite de Seguridad y Antivirus Open Source\"
description = \"Antivirus Open Source con EDR, Parches Virtuales y VPN de Doble Cifrado para Red Hat Enterprise Linux, Rocky Linux, AlmaLinux y Fedora\"
license = \"GPL-3.0\"
assets = [
  {assets_str}
]

[package.metadata.generate-rpm.requires]
webkit2gtk4_1 = \"*\"
gtk3 = \"*\"
tor = \"*\"
iptables = \"*\"
zenity = \"*\"

[package.metadata.generate-rpm.recommends]
policycoreutils = \"*\"
firewalld = \"*\"
'''

with open(os.path.join(root_dir, 'target', 'rpm_metadata.toml'), 'w') as fp:
    fp.write(toml_content)
"

echo "==> [Red Hat/Fedora] Construyendo paquete .rpm..."
RPM_BIN="${HOME}/.cargo/bin/cargo-generate-rpm"
if [ -x "${RPM_BIN}" ]; then
    (cd crates/samulibre-gui && "${RPM_BIN}" --metadata-overwrite ../../target/rpm_metadata.toml -o "../../target/${RPM_NAME}" --auto-req disabled)
elif command -v rpmbuild >/dev/null 2>&1; then
    BUILD_DIR="target/rpmbuild"
    rm -rf "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}/BUILD" "${BUILD_DIR}/RPMS" "${BUILD_DIR}/SOURCES" "${BUILD_DIR}/SPECS" "${BUILD_DIR}/SRPMS"
    cp target/release/samulibre-gui "${BUILD_DIR}/BUILD/"
    cp target/release/samulibre-cli "${BUILD_DIR}/BUILD/"
    cp data/samulibre.desktop "${BUILD_DIR}/BUILD/"
    cp assets/icon.png "${BUILD_DIR}/BUILD/"
    cp data/samulibre.service "${BUILD_DIR}/BUILD/"
    cp -r data/ui "${BUILD_DIR}/BUILD/"
    if [ -d "data/signatures" ]; then cp -r data/signatures "${BUILD_DIR}/BUILD/"; fi
    cp scripts/packaging/samulibre.spec "${BUILD_DIR}/SPECS/"
    rpmbuild --define "_topdir $(pwd)/${BUILD_DIR}" -bb "${BUILD_DIR}/SPECS/samulibre.spec"
    cp ${BUILD_DIR}/RPMS/*/*.rpm "target/${RPM_NAME}"
fi

echo "✔ Paquete .rpm para Red Hat/Fedora generado con éxito en: target/${RPM_NAME}"
