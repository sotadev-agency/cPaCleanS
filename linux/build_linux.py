"""Build script Linux — genera el binario cPacleanS con PyInstaller (ELF onefile).

Diferencias frente a build.py (Windows):
- separador ':' en --add-data (PyInstaller usa ';' en Windows, ':' en Linux/macOS).
- sin --icon: PyInstaller no embebe icono en binarios ELF; el icono de escritorio
  se resuelve via el .desktop (ver packaging/cpacleans.desktop + assets/icon.png).
- nombre de salida sin extension (cPacleanS, sin .exe).
"""
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent


def build():
    print("=" * 50)
    print("  cPacleanS — Build Linux")
    print("=" * 50)

    print("\n[1/3] Verificando dependencias...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(BASE_DIR / "requirements.txt")],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print("  Algunas dependencias opcionales fallaron (yara-python requiere compilador C).")
        print("  stderr:", result.stderr[-2000:])
        print("  Continuando con las dependencias disponibles...")

    print("\n[2/3] Compilando ejecutable...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=cPacleanS",
        "--onefile",
        "--windowed",
        f"--add-data=src/signatures:src/signatures",
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
    subprocess.check_call(cmd, cwd=BASE_DIR)

    exe_path = BASE_DIR / "dist" / "cPacleanS"
    if exe_path.exists():
        exe_path.chmod(0o755)
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n[3/3] dist/cPacleanS generado ({size_mb:.1f} MB)")
    else:
        print("\n  ADVERTENCIA: No se encontro el ejecutable")
        sys.exit(1)

    print("\nBuild completado. Empaquetado de escritorio: packaging/install.sh")


if __name__ == "__main__":
    build()
