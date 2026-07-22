# ESTADO — cPacleanS mejora autonoma

Archivo de reanudacion. Una sesion nueva lee SOLO este archivo + RESUME_TASK.md.
Actualizar al final de cada lote.

## Version
APP_VERSION = 3.1.6 (src/config/settings.py). Anterior: 3.1.5.
v3.1.6 (2026-07-21): nuevo ExecutableScanner (src/scanners/executable_scanner.py) por
observaciones de prueba (Observaciones.docx): denominaciones de malware que el motor
no reconocia (ejecutables Windows sueltos, doble extension, AutoIt, macros Office
downloader, exploit Equation Editor en RTF, PDF con /Launch o embebido ejecutable,
ZIP con PE embebido, XML con msxsl:script). Alcance limitado a rutas web/correo
(uploads, wp-content, public_html, mail/maildir), excluye vendor/node_modules/.git.
12 pruebas nuevas (tests/test_executable_scanner.py), todas PASS. Los 5 fallos de
unittest en verify.py (shell.php no encontrado, etc.) son el problema PREEXISTENTE de
Defender documentado abajo (confirmado con git stash: fallan igual sin este cambio).
v3.1.5 (2026-07-05): endurecimiento de deteccion (desofuscacion decode-and-rescan,
pase multilinea, decodificacion de partes MIME de correo). verify.py 4/4, 38 pruebas;
corpus legitimo sin hallazgos. Reduce evasion por ofuscacion/variantes sin bajar el
umbral (70) ni romper cero-FP.
v3.1.4 (2026-07-04): 3 fixes de la prueba GUI real (cancelar-en-extraccion, ventana
centrada, is_email sin falso positivo por '/tmp/').
EXE: dist/cPacleanS.exe recompilado a 3.1.5 el 5/07 (36.4 MB, exit 0); abre centrado
(valida fix ventana) y muestra v3.1.5. Se uso build.py directo porque en Windows
verify.py falla SOLO por Defender: cuarentena las muestras de webshell del corpus en
%TEMP% (confirmado en el Historial de Defender: shell.php/split.php a las 00:24). Para
verify 4/4 en Windows, excluir %TEMP% del antivirus.

## Re-verificacion auto-resume
- 2026-07-14: verify.py 4/4 PASS (38 pruebas) en copia /tmp; APP_VERSION 3.1.5.
  Sin cambios de codigo.
- 2026-07-21: corrida sin trabajo (no-op deliberado). Unico item pendiente [~] es manual
  en Windows; no se re-ejecuto verify para ahorrar creditos. Sin cambios de codigo.
- 2026-06-24..07-13: 20 corridas previas, mismo resultado. DoD (sandbox) cumplida.
RECOMENDADO (repetido 21x): DESACTIVAR la tarea "cPacleanS auto-resume". El unico item
[~] (release GitHub) es manual en Windows (gh autenticado), no automatizable aqui.

## Resultado v3.1.3 (2026-06-21) — verificado en copia consistente /tmp
- verify.py: 4/4 PASS. compileall OK; import no-GUI OK; lint_lite 0; unittest 31/31
  (14 previas + 17 nuevas de cleaners de BD). Antes los cleaners de BD no tenian test.
- Fix de deteccion: db_cleaner `_extract_post_rows` no consumia VALUES, perdiendo la
  PRIMERA tupla de cada INSERT de wp_posts (el primer post nunca se escaneaba). Hecho.
  Solo mejora recall; no borra contenido legitimo (umbral spram intacto). Regresion
  cubierta: sin el fix la suite da 2 fallos.
- Cero falsos positivos mantenido: filas legitimas (siteurl, post, comentario, fila
  no-protegida) intactas tras process(); control limpio sigue 0 hallazgos.
- Eficacia BD: spam (casino/viagra), fila critica CONCAT(0x..), usuarios peligrosos
  (conserva el mas antiguo + pass regenerada) y cron inseguro -> a:0:{} limpiados.

## Resultado v3.1.2 (2026-06-20)
- Suite recuperada (14 pruebas) y causa raiz AV identificada (ver seccion siguiente).

## Causa raiz resuelta (clave, no re-introducir)
- La suite desaparecia del disco cada sesion porque el ANTIVIRUS del equipo
  cuarentena archivos con firmas crudas tipo webshell. build_corpus.py persiste
  porque codifica los payloads en base64; las suites previas (test_cpacleans.py y la
  primera test_suite.py) tenian firmas literales y se borraban tras escribirse.
- Fix: tests/test_suite.py NO contiene firmas crudas — usa el corpus (base64) para
  las muestras y solo PHP benigno en los casos unitarios. Ahora persiste.
- Antes se atribuyo a "corrupcion del mount"; el mount si tiene latencia, pero la
  perdida real era el AV. Recomendacion: excluir la carpeta en el antivirus o
  mantener la convencion (cero firmas crudas en el repo).

## Tablero
- [x] Paso 0 contexto.
- [x] Baseline verificacion + tools/lint_lite.py.
- [x] Corpus fixtures.
- [x] Suite tests reconstruida y PERSISTENTE: tests/test_suite.py (14 pruebas).
- [x] Correccion por lotes (lint + dup-key + patrones).
- [x] Medicion efectividad e integridad (webshells, oraculo, YARA, hash).
- [x] Endurecer verify.py (falla con 0 pruebas) + causa raiz AV identificada.
- [x] Documentacion y versionado (3.1.3).
- [x] Cobertura cleaners de BD: tests/test_db_cleaner.py (17 pruebas) + fix
      _extract_post_rows (hueco primera tupla wp_posts). Era la ultima unidad
      autonoma viable en sandbox; ya no quedan unidades automatizables sin GUI/red.
- [x] Pruebas GUI reales en Windows (2026-07-04): dist/cPacleanS.exe v3.1.3 abre,
      carga backup, escanea, limpia->cuarentena, restaura CMS y genera reportes.
      Ver "Prueba GUI real". Falta solo: veredicto cero-FP del control 418MB.
- [x] Ejecutable Windows (.exe): dist/cPacleanS.exe v3.1.3 (build 22-jun) verificado
      funcional en la prueba GUI real. build_exe.bat/cPacleanS.spec onefile/windowed.
- [~] Release GitHub: RELEASE_NOTES y release bat existen (v3.1.1). PENDIENTE: bumpear
      a v3.1.3 y publicar en Windows con gh autenticado, tras generar el .exe.

## Residuales / proximos pasos
- Los 3 items [~] son SOLO manuales en Windows (GUI/exe/release). No hay mas trabajo
  autonomo de codigo viable en el sandbox -> ver "Como reanudar" (desactivar tarea).
- En Windows con red: ruff check src y pytest -q como verificacion extra.
- Opcional futuro (autonomo): mas casos BD (multi-INSERT por tabla, dumps .gz/.bz2,
  cascada postmeta) si se quiere subir cobertura; no es bloqueante.
- Validar contra un backup real grande de Descargas (scan_only) para FP.
- tests/test_cpacleans.py corrupto: ya ausente del disco; si reaparece, borrar manual.

## Entorno (importante)
Sandbox sin red: no se instala pytest/ruff/yara/clamav; toolchain stdlib. Para correr
pruebas, reconstruir copia /tmp desde el host. CLAVE: el AV del host cuarentena .py
con firmas crudas tipo webshell -> usar siempre base64 via build_corpus. El mount
ademas tiene latencia tras escribir; fuente de verdad = host (Read/Write/Edit).
- 2026-06-22: el mount de bash sirvio build_corpus.py TRUNCADO (5408 bytes, corte en
  build_infected_backup) mientras Grep/Read mostraban el archivo completo (224 lineas,
  return path/SQL_DUMP_EXPECT/build_wp_sql_dump presentes). Falsa alarma de mount, no
  defecto: reconstruir el .py en /tmp desde Read y verify.py da 4/4 (31 pruebas).
  Si una corrida ve "nothing to open"/None en el corpus, NO es regresion del repo;
  confirmar en Windows con: python tools/verify.py

## Prueba GUI real (2026-07-04, v3.1.3)
Ejecutada con dist/cPacleanS.exe (build 22-jun). Cubre DoD item 5 (y 6: exe funcional).
- Muestra AV-safe (Downloads/backup-test-infected.tar.gz: php-en-uploads, .user.ini
  auto_prepend, doble-ext; contenido benigno -> el AV del host NO la cuarentena):
  modo Normal -> 5 archivos, 3 detecciones CRITICAL, 0 confirmados, 1 en cuarentena.
  Verificado en disco: cuarentena_.../amenazas_removidas/report.php + copia intacta en
  originales_intactos/. Reportes HTML+PDF+JSON en Downloads/reportes/ + backup limpio
  backup-test-infected-limpio.tar.gz. Flujo cargar->escanear->limpiar->restaurar CMS->
  reportar->empaquetar OK. Cero FP destructivo: los .php benignos NO se tocaron.
- Control ltemagaz-limpio.tar.gz (418 MB, scan_only): validado como cPanel (anidado,
  homedir); extraccion en Windows impracticable (5% en 11 min, ETA ~3h) por el AV del
  host escaneando cada archivo. Veredicto cero-FP headless sobre 1590 archivos REALES
  del control (plugins/themes/codigo): 0 confirmados, 0 high/critical, 1 info -> cero FP
  se sostiene. Escaneo COMPLETO del 418MB pendiente en Windows con %TEMP%\malclean
  excluido del AV.
  ARTEFACTO (sandbox, NO defecto): extraer a ruta con '/tmp/' (o /new//cur//maildir/)
  hace que EmailScanner trate todo como correo y marque cada '<?php' como
  reinfection_risk (3517 falsos 'confirmados' desde /tmp; 0 desde /dev/shm). Medir
  SIEMPRE fuera de /tmp. [RESUELTO v3.1.4] is_email ya no se dispara por el substring
  '/tmp/'|'/new/'|'/cur/'; ahora exige .eml/.mbox o ruta con '/mail/'|'/maildir/'.
- Bugs/mejoras [(a) y (b) RESUELTOS v3.1.4; (c) es operativo]: (a) el .exe restauraba
  geometria fuera de pantalla -> ahora _center_on_screen; (b) CANCELAR no interrumpia la
  extraccion (self._engine era None en esa fase) -> BackupExtractor.cancel()/_cancelled +
  ExtractionCancelled y _cancel_scan cancela el extractor; (c) el acceso directo
  desplegado C:\Limpieza\cPacleanS\cPacleanS.exe fallo al abrir ("Failed to open path")
  -> reponer/reinstalar (posible cuarentena del AV).

## Como reanudar
Verificar en Windows: python tools/verify.py (4/4 PASS, 38 pruebas). CODIGO Terminado.
PENDIENTE manual: (1) publicar release v3.1.5: autenticar gh (gh auth login) y correr
release_v3.1.5.bat (crea tag, sube dist/cPacleanS.exe + RELEASE_NOTES_v3.1.5.md). Guia
completa en BUILD.md; (2) para verify 4/4 en Windows y el veredicto cero-FP del control
418MB, excluir %TEMP% (y %TEMP%\malclean) del Antivirus (pasos en BUILD.md). (build exe +
prueba GUI: HECHOS. build_only.bat compila sin verify si el AV rompe los tests.)
ACCION RECOMENDADA: DESACTIVAR la tarea "cPacleanS auto-resume" (solo confirmaria lo
hecho y gastaria creditos). Reactivar solo si hay nueva unidad de trabajo autonomo.
