# cPacleanS v3.1.1

Mantenimiento: recuperacion de la suite de pruebas y endurecimiento de la
verificacion. Sin cambios en el motor de deteccion ni en el scoring; la regla de
cero falsos positivos destructivos se mantiene intacta.

## Cambios
- Suite de pruebas reconstruida (tests/test_suite.py, 13 pruebas) contra el corpus
  determinista: corpus valido, cero falsos positivos en el backup de control
  limpio, deteccion de las 5 muestras inertes, regla .htaccess
  sospechoso-no-confirmado, integridad por hash en limpieza NORMAL e INTERMEDIA, y
  unidades de patrones webshell/backdoor e is_php_functional.
- tools/verify.py: el paso de pruebas ahora FALLA si no se descubren pruebas
  (antes, 0 pruebas pasaba en silencio). Reporta el conteo.

## Verificacion
`python tools/verify.py` -> 4/4 PASS (compileall, import, lint_lite, unittest 13/13).

## Comportamiento (sin cambio de codigo)
Las muestras inertes minimas puntuan 55 (umbral 70), por lo que en modo NORMAL no
se auto-limpian los webshells de la raiz ni los .htaccess (conservador, por
seguridad); en INTERMEDIO/ESTRICTO se eliminan las 5. En todos los modos: cero
falsos positivos destructivos (archivos legitimos con hash identico).

## Descarga
cPacleanS.exe — Windows, build PyInstaller onefile/windowed.
