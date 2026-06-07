"""Build script — genera ejecutable cPacleanS con PyInstaller."""
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent


def build():
    print("=" * 50)
    print("  cPacleanS — Build")
    print("=" * 50)

    print("\n[1/3] Verificando dependencias...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(BASE_DIR / "requirements.txt")],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print("  Algunas dependencias opcionales fallaron (yara-python requiere compilador C++).")
        print("  Continuando con las dependencias disponibles...")

    print("\n[2/3] Compilando ejecutable...")
    icon_arg = f"--icon={BASE_DIR / 'assets' / 'icon.ico'}" if (BASE_DIR / "assets" / "icon.ico").exists() else ""
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=cPacleanS",
        "--onefile",
        "--windowed",
        icon_arg,
        "--add-data=src/signatures;src/signatures",
        f"--distpath={BASE_DIR / 'dist'}",
        f"--workpath={BASE_DIR / 'build_temp'}",
        f"--specpath={BASE_DIR}",
        "--hidden-import=customtkinter",
        "--hidden-import=jinja2",
        "--hidden-import=requests",
        "--hidden-import=chardet",
        "--hidden-import=fpdf",
        "--hidden-import=multiprocessing",
        "--collect-all=customtkinter",
        "--noconfirm",
        str(BASE_DIR / "main.py"),
    ]
    cmd = [c for c in cmd if c]
    subprocess.check_call(cmd)

    exe_path = BASE_DIR / "dist" / "cPacleanS.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n[3/3] cPacleanS.exe generado ({size_mb:.1f} MB)")
    else:
        print("\n  ADVERTENCIA: No se encontro el ejecutable")

    print("\nBuild completado. Inno Setup: installer/setup.iss")


if __name__ == "__main__":
    build()
