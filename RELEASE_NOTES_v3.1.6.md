# cPacleanS v3.1.6

Nuevo scanner de ejecutables/macros/exploits disfrazados, a partir de una revision
de denominaciones de malware que el motor no reconocia (adjuntos/uploads Windows en
lugar de webshells PHP).

## Cambios

Deteccion (nuevo — ExecutableScanner)
- Doble extension documento+ejecutable (ej. `comprobante.pdf.exe`).
- Extension ejecutable/script de alto riesgo (.exe/.scr/.com/.pif/.cpl/.msi/.vbs/.vbe/
  .jse/.wsf/.wsh/.hta/.bat/.cmd) dentro de contenido web/correo.
- Ejecutable (cabecera PE "MZ") con extension no ejecutable — disfrazado como .tmp,
  .dat, .bin, etc.
- Firma de binario compilado con AutoIt (patron habitual de Formbook/Agensla).
- Script .au3 con llamadas Run/ShellExecute/InetGet/FileInstall/DllCall (alto); presencia
  sin llamadas peligrosas (medio) — sin uso legitimo en hosting web.
- RTF con objeto OLE Equation Editor embebido (patron de explotacion CVE-2017-11882 /
  CVE-2018-0802).
- Documentos Office (OLE legacy y OOXML via vbaProject.bin) con macro autoejecutable
  (AutoOpen/Document_Open/etc.) combinada con llamadas de descarga/ejecucion (downloader).
- PDF con accion /Launch, archivo embebido ejecutable, o JavaScript con codificacion
  sospechosa.
- ZIP con ejecutable (PE) embebido en alguno de sus miembros.
- XML con namespace `msxsl:script` o `language=JScript/VBScript` (tecnica Squiblydoo).

Alcance limitado a rutas web/correo (uploads, wp-content, public_html, mail/maildir,
etc.), excluyendo vendor/node_modules/.git — evita falsos positivos sobre el resto de
un backup completo de cPanel.

## Verificacion
`python -m unittest tests.test_executable_scanner -v` -> 12/12 PASS.

Nota (Windows con Defender): `tools/verify.py` reporta 5 fallos en la suite general por
el problema PREEXISTENTE ya documentado (Defender cuarentena las muestras de webshell
del corpus en `%TEMP%`); confirmado que son identicos con o sin este cambio (`git stash`).
No es un defecto de este release. Build con `build_only.bat` (omite verify).

## Descarga
cPacleanS.exe (~39.8 MB) — Windows, build PyInstaller onefile/windowed.
