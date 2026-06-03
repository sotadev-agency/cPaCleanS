@echo off
cd /d "%~dp0"
echo Inicializando repositorio...
git init
echo Creando .gitignore...
(
echo node_modules/
echo dist/
echo build/
echo __pycache__/
echo *.pyc
echo .env
) > .gitignore
echo Agregando archivos...
git add .
echo Haciendo commit...
git commit -m "Initial commit - cPacleanS Malware Cleanup v2.0.0"
echo Configurando remote...
git branch -M main
git remote add origin https://github.com/sotadev-agency/proyectos-ia.git
echo Subiendo a GitHub...
git push -u origin main
echo.
echo === PROCESO COMPLETADO ===
pause
