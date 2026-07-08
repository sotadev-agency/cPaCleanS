# Compilar y publicar cPacleanS (Windows)

## Requisitos
- Python 3.10+ en PATH (probado con 3.14.5). `build.py` instala las dependencias de
  `requirements.txt` (yara-python es opcional; si falla por falta de compilador C++,
  el build continua).
- Para publicar: GitHub CLI `gh` instalado y autenticado (`gh auth login`), con el
  remoto `origin` configurado.

## Compilar el ejecutable

Opcion A (recomendada, con verificacion previa):

    build_exe.bat

Corre `tools/verify.py` (compileall, import, lint_lite, unittest) y, si pasa 4/4,
`build.py` (PyInstaller onefile/windowed) -> `dist\cPacleanS.exe`.

Opcion B (sin verificacion):

    build_only.bat

Corre solo `build.py`. Usar cuando el antivirus rompe la etapa de pruebas (ver
seccion siguiente). El exe empaqueta unicamente `src/` y `main.py`, no el corpus de
pruebas, por lo que omitir el verify no afecta al binario.

## Antivirus: por que `verify.py` puede fallar en Windows

La suite escribe muestras de webshell inertes en `%TEMP%` al correr los tests.
Windows Defender las cuarentena por firma (p. ej. `shell.php` con
`eval(base64_decode($_POST...))`), asi que el archivo desaparece antes de que el
scanner lo lea y algunas pruebas de deteccion fallan. Esto se confirma en:

    Seguridad de Windows > Proteccion contra virus y amenazas > Historial de proteccion

No es un defecto del codigo: `compileall`, `import` y `lint_lite` pasan, y la suite
pasa 38/38 en un entorno sin ese antivirus (p. ej. el sandbox de CI).

### Solucion: excluir %TEMP% del antivirus

    Seguridad de Windows > Proteccion contra virus y amenazas > Administrar la
    configuracion > Exclusiones > Agregar o quitar exclusiones > Agregar una
    exclusion > Carpeta

Agregar:
- `%TEMP%`  (normalmente `C:\Users\<usuario>\AppData\Local\Temp`)
- opcional pero recomendado: `%TEMP%\malclean` — carpeta donde cPacleanS extrae los
  backups. Excluirla acelera mucho el escaneo de backups grandes (hoy se ralentiza
  porque el AV escanea en tiempo real cada archivo extraido).

Tras excluir, `build_exe.bat` corre `verify.py` 4/4 y compila.

## Publicar el release en GitHub

Con `dist\cPacleanS.exe` generado y `gh` autenticado:

    release_v3.1.5.bat

Crea el tag `v3.1.5`, lo empuja a `origin`, crea el release con las notas
(`RELEASE_NOTES_v3.1.5.md`) y sube el exe como asset.

Equivalente manual:

    git tag -a v3.1.5 -m "cPacleanS v3.1.5"
    git push origin v3.1.5
    gh release create v3.1.5 dist\cPacleanS.exe --title "cPacleanS v3.1.5" --notes-file RELEASE_NOTES_v3.1.5.md

Si el release ya existe y solo hay que resubir el exe:

    gh release upload v3.1.5 dist\cPacleanS.exe --clobber
