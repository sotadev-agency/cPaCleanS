#!/usr/bin/env bash
# Instala cPacleanS para el usuario actual: copia el binario a ~/.local/bin,
# registra el icono y el lanzador en el menu de aplicaciones (XDG desktop).
# No requiere root ni un instalador tipo Windows (Inno Setup) — es la forma
# estandar de instalar apps de usuario en un escritorio Linux (GNOME/KDE/XFCE).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
BIN_SRC="$REPO_ROOT/dist/cPacleanS"

if [ ! -f "$BIN_SRC" ]; then
    echo "No se encontro $BIN_SRC. Compila primero con: python3 build_linux.py" >&2
    exit 1
fi

BIN_DIR="$HOME/.local/bin"
ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"
APPS_DIR="$HOME/.local/share/applications"

mkdir -p "$BIN_DIR" "$ICON_DIR" "$APPS_DIR"

install -m 755 "$BIN_SRC" "$BIN_DIR/cPacleanS"
install -m 644 "$REPO_ROOT/assets/icon.png" "$ICON_DIR/cpacleans.png"

sed "s#__INSTALL_BIN__#$BIN_DIR/cPacleanS#" \
    "$SCRIPT_DIR/cpacleans.desktop" > "$APPS_DIR/cpacleans.desktop"
chmod 644 "$APPS_DIR/cpacleans.desktop"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS_DIR" || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f "$HOME/.local/share/icons/hicolor" || true
fi

echo "cPacleanS instalado en $BIN_DIR/cPacleanS"
echo "Disponible en el menu de aplicaciones (categoria Utilidades/Seguridad)."
echo "Tambien puedes ejecutarlo directamente: $BIN_DIR/cPacleanS"
