# Changelog cPacleanS

Versionado semantico. Formato: cambios por version, mas recientes arriba.

## v3.1.1 (2026-06-19)

Recuperacion de la suite de pruebas y endurecimiento de la verificacion. Sin
cambios en el motor ni en el scoring (regla de cero falsos positivos intacta).

Correcciones
- tests/test_cpacleans.py se habia perdido (bloques corruptos en disco: la entrada
  de directorio existia pero el archivo era ilegible; nunca commiteado a git).
  Efecto: `unittest discover` corria 0 pruebas y verify.py daba PASS falso. Suite
  reconstruida contra el corpus determinista: 13 pruebas (corpus valido, cero FP en
  control limpio, deteccion de las 5 muestras inertes, regla .htaccess
  sospechoso-no-confirmado, integridad por hash en modos NORMAL e INTERMEDIO,
  unidad de patrones webshell/backdoor e is_php_functional).
- tools/verify.py: el paso unittest ahora FALLA si tests/ no existe o si se
  descubren 0 pruebas (antes pasaba en silencio); reporta el conteo de pruebas.

Comportamiento medido (documentado, sin cambio de codigo)
- Las muestras inertes minimas puntuan 55 (<70 umbral), por lo que no quedan
  confirmed_malware. En NORMAL (por defecto) solo se barre el .php de uploads y los
  .htaccess quedan sospechosos; los webshells de la raiz no se auto-limpian. En
  INTERMEDIO/ESTRICTO se eliminan las 5 muestras. En todos los modos: cero falsos
  positivos destructivos (legitimos con hash identico). Pendiente de decision:
  si un webshell inequivoco minimo debe auto-confirmar en NORMAL, midiendo FP
  contra un corpus real antes de tocar el scoring.

## v3.1.0 (2026-06-19)

Mantenimiento de seguridad y calidad de codigo. Sin cambios incompatibles.

Deteccion (efectividad)
- Nuevo patron backdoor por indireccion: `eval/assert` sobre funcion variable
  (ej. `$x="base64_decode"; eval($x(...))`). Evasion antes no confirmada; ahora
  se confirma y cuarentena. Riesgo de falso positivo muy bajo.
- Nuevo patron ofuscacion: asignacion de nombre de funcion peligrosa a variable.

Calidad de codigo
- Eliminados 6 imports sin usar: spam_post_cleaner (Optional), gui/app (sys),
  report/generator (os), cms_scanner (os, hashlib), yara_scanner (os).
- generator.py `_UNICODE_MAP`: corregida clave duplicada (`‘`); el mapeo de
  espacio duro (nbsp) queda explicito. Sin cambio de comportamiento.

Pruebas e infraestructura
- Nuevo corpus versionado y determinista: tests/fixtures/build_corpus.py
  (backup limpio de control + backup infectado inerte; payloads en base64, EICAR
  ensamblado en runtime; no se almacena malware vivo en el repo).
- Nueva suite unittest (compatible con pytest): tests/test_cpacleans.py
  (lint, deteccion de patrones, integracion escaneo->limpieza con integridad por
  hash, cero falsos positivos, utilidades). 9 pruebas.
- Nuevas herramientas sin dependencias de red:
  - tools/lint_lite.py: linter offline AST (F401, F403, E722, B006, E711, F601).
  - tools/verify.py: compile + import + lint + unittest en un comando.
  - tools/independent_check.py: oraculo de deteccion independiente + EICAR +
    validacion estructural de reglas YARA.

Resultados medidos (en copia consistente)
- Lint: 0 hallazgos (antes 11). compileall y 33 imports no-GUI: OK.
- Pruebas: 9/9.
- Integridad: 8 archivos legitimos con hash identico antes/despues de limpieza
  Normal; 0 eliminados, 0 modificados.
- Cero falsos positivos en backup de control (0 confirmados).
- Efectividad: webshell, backdoor doble-extension y backdoor por indireccion
  confirmados y cuarentenados; el oraculo independiente coincide en las 3
  muestras de web-malware. 6 archivos YARA (35 reglas) estructuralmente validos.

## v3.0.x (2026-06)
- v3.0.0: auditoria completa, reglas YARA, IoC, validacion de backup, export JSON,
  UI rediseñada; correcciones de residuos, spam BD, core WP y dominio en reportes.
- v3.0.1 / v3.0.2: ajustes de empaquetado y metadata de version (working tree).

## v2.6.x (2026-06)
- WordPressCleaner, JunkCleaner, SpamPostCleaner, CMSFullWiper, modo critico cPanel,
  mailer backdoors, endurecimiento de BD, drop-ins de wp-content, version pre-wipe.

## v2.3.0 (2026-06)
- BD: parser SQL robusto (.sql.bz2), prefijos dinamicos, tablas protegidas,
  limpieza por fila. Plugins: lee activos desde BD, reinstala desde WP.org.
  Reportes con seccion BD. Fix Moodle fantasma.

## v2.2.x (2026-06)
- Modo "solo contenido critico", restauracion Joomla/Moodle/Laravel/OJS,
  separacion plugins/temas, backup parcial cPanel, validador de API key VT.

## v2.0.0 - v2.1.0 (2026-06)
- Migracion a multiprocessing, cuarentena segura con copia original, reportes
  HTML+PDF, limpieza de archivos 0KB, fix de truncado de nombres.
