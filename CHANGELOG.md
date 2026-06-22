# Changelog cPacleanS

Versionado semantico. Formato: cambios por version, mas recientes arriba.

## v3.1.3 (2026-06-21)

Cobertura de los cleaners de BD (antes sin pruebas) y correccion de un hueco de
deteccion encontrado al escribirlas. Regla de cero falsos positivos intacta.

Fix (deteccion)
- src/cleaners/db_cleaner.py `_extract_post_rows`: el regex no consumia `VALUES`,
  por lo que "VALUES " contaminaba la PRIMERA tupla de cada INSERT de wp_posts y
  `_parse_post_tuple` la descartaba (ID 0). Resultado: el primer post de cada INSERT
  nunca se analizaba para spam. Ahora consume la lista de columnas opcional y VALUES,
  igual que `_collect_wp_users` / `_extract_comment_rows` / `_delete_tuples_by_id`.
  Solo mejora la recall; no puede borrar contenido legitimo (umbral de spam intacto).

Pruebas (nuevas, +17 => 31 total)
- tests/test_db_cleaner.py: parsing SQL (_split_sql_values / _split_value_tuples con
  comillas simples/dobles, comas y parentesis dentro de strings); scoring
  SpamPostCleaner (post_type seguro omitido, spam eliminado, scan_only sin borrar,
  post legitimo intacto, proteccion por comentarios con score moderado, comentario
  phishing); integracion DBCleaner.process() sobre un dump WP (spam, fila critica
  CONCAT(0x..), usuarios peligrosos conservando el mas antiguo + pass regenerada,
  cron neutralizado a a:0:{}) con filas legitimas intactas; regresion del fix:
  el post spam en PRIMERA posicion se extrae y se elimina (sin el fix, 2 fallos).
- tests/fixtures/build_corpus.py: `build_wp_sql_dump()` genera el dump determinista.
  Unico fragmento sensible (valor cron) en base64 (`_B64['cron_evil']`); resto SQL
  benigno. Convencion anti-AV respetada (cero firmas crudas en el repo).
- verify.py: 4/4 PASS (compile, import, lint_lite 0, unittest 31/31) en copia /tmp.

## v3.1.2 (2026-06-20)

Recuperacion REAL de la suite de pruebas y causa raiz identificada. Sin cambios en
el motor ni en el scoring (regla de cero falsos positivos intacta).

Causa raiz (resuelta)
- La suite desaparecia del disco cada sesion porque el antivirus del equipo
  cuarentena los archivos que contienen firmas crudas tipo webshell. Por eso
  build_corpus.py (payloads en base64, ensamblados en runtime) si persistia, pero
  test_cpacleans.py y la primera test_suite.py se borraban tras escribirse. Antes
  se atribuyo a "corrupcion del mount" (sintoma, no causa).
- Fix: tests/test_suite.py NO almacena firmas crudas. Reutiliza el corpus (base64)
  para las muestras inertes y usa solo PHP benigno en los casos unitarios. Asi el
  archivo persiste en disco y verify.py descubre las pruebas.

Pruebas
- tests/test_suite.py reconstruida: 14 pruebas unittest (corpus valido; deteccion de
  las 5 muestras inertes; is_php_functional; cero FP en control; integridad por hash
  en NORMAL e INTERMEDIO; eficacia ESTRICTO elimina las 5; INTERMEDIO elimina el
  webshell de raiz; NORMAL barre el .php de uploads).
- verify.py: 4/4 PASS (compile, import, lint_lite 0, unittest 14/14) en copia
  consistente /tmp.

Recomendacion operativa
- Excluir la carpeta del proyecto en el antivirus, o mantener la convencion de no
  escribir firmas crudas en el repo (solo base64 via build_corpus).

APP_VERSION 3.1.1 -> 3.1.2.

## v3.1.1 (2026-06-19)

Recuperacion de la suite de pruebas y endurecimiento de la verificacion. Sin
cambios en el motor ni en el scoring (regla de cero falsos positivos intacta).

Correcciones
- tests/test_cpacleans.py se habia perdido (bloques corruptos en disco: la entrada
  de directorio existia pero el archivo era ilegible; nunca commiteado a git).
  Efecto: `unittest discover` corria 0 pruebas y verify.py daba PASS falso. Suite
  reconstruida en tests/test_suite.py (ruta nueva: la corrupta no se pudo borrar
  desde el entorno) contra el corpus determinista: 13 pruebas (corpus valido, cero
  FP en control limpio, deteccion de las 5 muestras inertes, regla .htaccess
  sospechoso-no-confirmado, integridad por hash en modos NORMAL e INTERMEDIO,
  unidad de patrones webshell/backdoor e is_php_functional). Borrar manualmente en
  Windows el archivo corrupto tests/test_cpacleans.py.
- tools/verify.py: el paso unittest ahora FALLA si tests/ no existe o si se
  descubren 0 pruebas (antes pasaba en silencio); reporta el conteo de pruebas.

Empaquetado y entrega (Windows)
- Build ya existente revisado: main.py -> src.gui.app, cPacleanS.spec (onefile,
  windowed, assets/icon.ico) y build.py (instala deps + compila a dist/cPacleanS.exe).
- Nuevos scripts: build_exe.bat (verify + build), release_v3.1.1.bat (tag + gh
  release create + upload + gh release view) y RELEASE_NOTES_v3.1.1.md. El .exe y el
  release se generan/publican en Windows (PyInstaller no cross-compila; gh requiere
  red y credenciales).

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
