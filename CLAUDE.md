# CLAUDE.md — guia para sesiones de Claude en cPacleanS

Leer ANTES de modificar. Complementa CONTEXTO_PROYECTO.md (arquitectura) y
ESTADO.md (estado vivo). Texto pragmatico, sin iconos.

## Que es
Herramienta de escritorio (Windows, Python 3.10+ / CustomTkinter) que escanea y
limpia malware de backups cPanel (.tar.gz/.zip) de sitios WordPress/Joomla/Moodle/
OJS/Laravel. Salida: reporte HTML+PDF+JSON, cuarentena, core CMS restaurado,
backup limpio. APP_VERSION en src/config/settings.py.

## Reglas de seguridad (criticas, no romper)
- Cero falsos positivos destructivos: archivos legitimos no se tocan.
- Cuarentena guarda copia original antes de mover/eliminar (salvo modo strict).
- scan_only nunca modifica archivos.
- Nunca eliminar tablas BD completas: solo filas con malware critico confirmado.
- confirmed_malware se decide por score >= confidence_threshold (70). No bajar el
  umbral sin medir falsos positivos contra el corpus.
- Patrones .htaccess (redirect/handler) quedan como sospechosos (revision manual),
  no auto-confirmados, para no destruir .htaccess legitimos.

## Verificacion (obligatoria tras cada cambio)
    python tools/verify.py
Ejecuta: compileall src, import de modulos no-GUI, tools/lint_lite.py src,
unittest discover tests. Debe quedar todo PASS.
En Windows con red, complementar: ruff check src && pytest -q

## Anadir un patron de deteccion
- PHP/JS/.htaccess: editar listas en src/scanners/php_scanner.py
  (PHP_PATTERNS, JS_PATTERNS, HTACCESS_PATTERNS). Si la deteccion debe auto-limpiar
  en modo Normal, la categoria debe estar en CONFIRMED_MALWARE_CATEGORIES
  (src/core/engine.py) y el score total superar 70.
- Tras anadir, agregar una prueba en tests/test_cpacleans.py y correr verify.

## Optimizacion de tokens / metodo
- Editar por diffs; no volcar archivos completos.
- Confiar en ESTADO.md para reanudar; no re-leer todo el historial.
- Medir siempre contra el corpus fijo (tests/fixtures/build_corpus.py).

## Nota de entorno (sandbox Linux de Cowork)
- Sin red: no se instalan pytest/ruff/yara/clamav; se usa la toolchain stdlib.
- El mount puede tener latencia de lectura tras escribir; verificar contenido en el
  host con Grep/Read y, para correr pruebas, trabajar sobre una copia local en /tmp.
