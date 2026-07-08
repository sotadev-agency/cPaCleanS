# cPacleanS v3.1.5

Endurecimiento de la deteccion frente a amenazas ofuscadas y nuevas variantes, mas
las correcciones surgidas de la prueba GUI real (v3.1.4). Sin bajar el umbral de
confianza (70); la regla de cero falsos positivos destructivos se mantiene intacta.

## Cambios

Deteccion (v3.1.5)
- Desofuscacion (decode-and-rescan): decodifica blobs base64/hex literales (con capa
  opcional gzinflate/gzip/rot13) y re-escanea el PAYLOAD con patrones de ejecucion de
  alta especificidad. Revela variantes que reencodifican payloads conocidos aunque el
  fuente solo muestre el blob; solo marca si el contenido decodificado ejecuta, por lo
  que blobs benignos (imagenes, JSON, tokens) no generan hallazgos.
- Pase multilinea: busca las construcciones de ejecucion sobre TODO el contenido (no
  linea a linea), atrapando el malware que reparte la llamada en varias lineas para
  evadir el escaneo linea-a-linea.
- Correos: decodifica cada parte MIME (get_payload) y marca ejecutables (cabecera
  PE/ELF) o payloads script/PHP ocultos por base64 en el cuerpo o adjuntos del correo.

Correcciones (v3.1.4, incluidas en este release)
- CANCELAR interrumpe tambien la fase de extraccion (antes solo se comprobaba en el
  escaneo, por lo que no detenia la extraccion).
- La ventana se abre centrada en el monitor primario (evita que aparezca fuera de
  pantalla si el gestor de ventanas restaura una geometria antigua).
- EmailScanner: is_email deja de activarse por el substring '/tmp/' | '/new/' |
  '/cur/'; solo trata como correo lo que esta bajo un arbol real (.eml/.mbox o rutas
  con /mail/ | /maildir/). Elimina un falso positivo masivo cuando el sitio o la ruta
  temporal contienen una carpeta tmp/.

## Verificacion
`python tools/verify.py` -> 4/4 PASS (compileall, import, lint_lite, unittest 38/38).

Nota (Windows con Defender): excluye %TEMP% del antivirus antes de correr verify. Si
no, Defender pone en cuarentena las muestras de webshell inertes del corpus en %TEMP%
y algunas pruebas de deteccion fallan (no es defecto del codigo; la suite pasa 38/38
en un entorno sin ese AV). Ver BUILD.md. Alternativa: build_only.bat compila sin la
etapa de pruebas.

## Descarga
cPacleanS.exe (~36.4 MB) — Windows, build PyInstaller onefile/windowed.
