@echo off
cd /d "%~dp0"
echo ============================================================
echo   cPacleanS v3.1.5 - build directo (omite verify)
echo   Nota: verify.py falla SOLO porque el antivirus pone en
echo   cuarentena las muestras de webshell del corpus en %%TEMP%%.
echo   El exe empaqueta unicamente src/ y main.py (sin corpus).
echo ============================================================
echo.
python build.py
echo.
echo === FIN build. Codigo de salida: %errorlevel% ===
pause
