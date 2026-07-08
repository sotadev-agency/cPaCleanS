@echo off
REM ============================================================
REM  Publica el release v3.1.5 en GitHub (Windows).
REM  Requisitos:
REM   - GitHub CLI 'gh' instalado y autenticado (gh auth login).
REM   - dist\cPacleanS.exe ya generado (build_exe.bat o build_only.bat).
REM   - Repositorio git con remoto 'origin' configurado.
REM ============================================================
setlocal
cd /d "%~dp0"
set TAG=v3.1.5
set EXE=dist\cPacleanS.exe
set NOTES=RELEASE_NOTES_v3.1.5.md

where gh >nul 2>nul
if errorlevel 1 (
  echo ERROR: GitHub CLI 'gh' no esta instalado o no esta en PATH.
  echo Instala desde https://cli.github.com/ y ejecuta: gh auth login
  pause & exit /b 1
)
if not exist "%EXE%" (
  echo ERROR: no existe %EXE%. Ejecuta build_exe.bat o build_only.bat primero.
  pause & exit /b 1
)
if not exist "%NOTES%" (
  echo ERROR: no existe %NOTES%.
  pause & exit /b 1
)

echo === Release %TAG% ===
echo [1/3] Creando tag local y empujando a origin...
git tag -a %TAG% -m "cPacleanS %TAG%" 2>nul
git push origin %TAG%

echo [2/3] Creando release y subiendo %EXE%...
gh release create %TAG% "%EXE%" --title "cPacleanS %TAG%" --notes-file "%NOTES%"
if errorlevel 1 (
  echo.
  echo Si el release ya existe, sube el asset con:
  echo   gh release upload %TAG% "%EXE%" --clobber
  pause & exit /b 1
)

echo [3/3] Verificando release publicado...
gh release view %TAG%
echo.
echo Listo.
pause
endlocal
