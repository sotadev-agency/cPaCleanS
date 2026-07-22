# cPacleanS — build Linux

Puerto Linux de cPacleanS (limpiador de malware para backups de cPanel), en esta
carpeta separada de `src/` (build Windows) en la raiz del repo. Mismo motor y GUI
(customtkinter/Tkinter, ya multiplataforma); solo se adaptaron las rutas de
configuracion (XDG en vez de `%APPDATA%`) y la apertura de archivos (`xdg-open`
en vez de `os.startfile`).

## Requisitos del sistema

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-tk libmagic1 build-essential
```

`python3-tk` es necesario para la GUI (Tkinter); `libmagic1` para deteccion de
tipo de archivo; `build-essential` solo si `yara-python` compila desde fuente.

## Ejecutar desde codigo fuente

```bash
cd linux
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

## Compilar el binario (PyInstaller, onefile)

```bash
cd linux
python3 build_linux.py
```

Genera `linux/dist/cPacleanS` (ELF de un solo archivo, sin dependencias de Python
en el sistema destino salvo libmagic1/Tk en tiempo de ejecucion segun distro).

## Instalar en el menu de aplicaciones (integracion nativa del escritorio)

```bash
./packaging/install.sh
```

Copia el binario a `~/.local/bin/cPacleanS`, el icono a
`~/.local/share/icons/hicolor/256x256/apps/` y el lanzador `.desktop` a
`~/.local/share/applications/` — aparece en el menu de aplicaciones (GNOME/KDE/
XFCE/etc.) sin necesidad de un instalador con privilegios de root, a diferencia
del `.exe`/Inno Setup de Windows.

## Verificar (tests + lint, sin GUI)

```bash
python3 tools/verify.py
```

Igual que en Windows: 4 fases (compileall, import no-GUI, lint_lite, unittest).
A diferencia de Windows, aqui NO hay problema de antivirus poniendo en cuarentena
las muestras de test (Linux no tiene un AV equivalente a Defender por defecto),
por lo que la suite deberia dar 4/4 de forma consistente en CI.

## CI / Release

`.github/workflows/build-linux.yml` (en la raiz del repo) compila este binario en
un runner `ubuntu-latest` via GitHub Actions y lo adjunta a un release con tag
`linux-vX.Y.Z`. Se dispara manualmente (`workflow_dispatch`) o al pushear un tag
`linux-v*`.
