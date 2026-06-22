@echo off
REM ============================================================
REM  cPacleanS v3.1.1 - verificacion + build del .exe (Windows)
REM  Genera dist\cPacleanS.exe (PyInstaller onefile, windowed).
REM  Requisitos: Python 3.10+ en PATH. build.py instala las deps.
REM ============================================================
setlocal
cd /d "%~dp0"
echo === cPacleanS v3.1.1 : verificacion + build ===

where python >nul 2>nul
if errorlevel 1 (
  echo ERROR: Python no esta en PATH.
  pause & exit /b 1
)

echo.
echo [1/2] Verificando ^(tools\verify.py^)...
python tools\verify.py
if errorlevel 1 (
  echo.
  echo VERIFICACION FALLIDA - build abortado.
  pause & exit /b 1
)

echo.
echo [2/2] Compilando ejecutable ^(build.py / PyInstaller^)...
python build.py
if errorlevel 1 (
  echo.
  echo BUILD FALLIDO.
  pause & exit /b 1
)

echo.
if exist "dist\cPacleanS.exe" (
  echo OK: dist\cPacleanS.exe generado.
) else (
  echo ADVERTENCIA: no se encontro dist\cPacleanS.exe
)
pause
endlocal
