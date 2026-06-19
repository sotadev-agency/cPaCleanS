# Guia para reportar fallas y mejoras a Claude — Optimizar tokens

## Principio clave

Claude cobra por tokens (texto procesado). Cuanto mas preciso y corto sea tu reporte, menos tokens usa y mejor resultado obtienes.

**NO hagas esto** (gasta tokens innecesariamente):
> "Hola Claude, tengo un problema con el programa que hiciste, no me funciona bien, cuando le doy click al boton de escanear se queda pensando y luego no pasa nada, no se que sera, puedes ayudarme? el programa es el que limpia malware de cpanel que hicimos la otra vez..."

**SI haz esto** (preciso, directo, minimos tokens):
> "cPacleanS error: click Escanear con backup de 2GB, se congela en 'Escaneando...', no avanza de 0%. Log: ninguno. Windows 11, 8GB RAM."

---

## Plantilla para reportar FALLAS (copiar y pegar)

```
BUG cPacleanS v3.1.0

QUE: [descripcion en 1 linea]
CUANDO: [que estabas haciendo exactamente]
BACKUP: [tamano del archivo, formato]
MODO: [solo escaneo / normal / intermedio / estricto]
ERROR: [mensaje exacto o comportamiento]
LOG: [ultimas 5 lineas del log si las hay]
SO: [Windows 10/11, RAM]
REPRODUCE: [siempre / a veces / solo una vez]
```

### Ejemplo real:

```
BUG cPacleanS v3.1.0

QUE: PDF se genera vacio (0 KB)
CUANDO: despues de escanear backup de Joomla
BACKUP: 800MB .tar.gz, cuenta con 3 sitios Joomla
MODO: solo escaneo
ERROR: PDF: 0 bytes, HTML funciona bien
LOG: "ERROR: 'charmap' codec can't encode character"
SO: Windows 11, 16GB RAM
REPRODUCE: siempre con backups que tienen caracteres especiales en rutas
```

---

## Plantilla para solicitar MEJORAS (copiar y pegar)

```
MEJORA cPacleanS

QUE: [que quieres que haga]
POR QUE: [problema que resuelve o beneficio]
EJEMPLO: [como se veria o usaria]
PRIORIDAD: [alta / media / baja]
```

### Ejemplo real:

```
MEJORA cPacleanS

QUE: agregar escaneo de archivos .py (Python)
POR QUE: algunos hostings tienen apps Django/Flask con malware
EJEMPLO: detectar eval(), exec(), os.system() en archivos .py del backup
PRIORIDAD: media
```

---

## Plantilla para solicitar MULTIPLES cambios en una sesion

Cuando tengas varias cosas, agrupalas asi para que Claude las procese en una sola pasada:

```
cPacleanS — LOTE DE CAMBIOS

BUGS:
1. [bug corto]
2. [bug corto]

MEJORAS:
1. [mejora corta]
2. [mejora corta]

CONTEXTO: [solo si es necesario, 1-2 lineas]
ARCHIVOS AFECTADOS: [si los conoces]
```

### Ejemplo real:

```
cPacleanS — LOTE DE CAMBIOS

BUGS:
1. PDF falla con backups >1GB (error memoria)
2. Barra de progreso no avanza durante extraccion de .zip

MEJORAS:
1. Agregar boton "Abrir carpeta de cuarentena"
2. Mostrar tiempo estimado restante durante escaneo

ARCHIVOS AFECTADOS: src/report/generator.py, src/gui/app.py
```

---

## Tips para gastar menos tokens

| Haz esto | En vez de esto |
|----------|---------------|
| Pega el error exacto | "me salio un error rojo" |
| Di el archivo si lo sabes | "algo del codigo del scanner" |
| Una sesion = un tema | Mezclar 5 temas distintos |
| Referencia la version | "el programa que hicimos" |
| Usa las plantillas de arriba | Texto libre sin estructura |
| Si Claude ya tiene el codigo, di "en src/gui/app.py linea X" | Pegar todo el archivo |
| Di "corregir y recompilar" | Describir paso a paso que quieres que haga |

---

## Como iniciar sesion con Claude para cambios

Primer mensaje ideal (minimo contexto, maximo resultado):

```
Proyecto: cPacleanS v3.1.0
Ruta: C:\Users\SSW\Documents\limpiador_malware
Stack: Python + CustomTkinter + PyInstaller

[tu bug o mejora usando la plantilla]
```

Claude automaticamente leera los archivos del proyecto y aplicara los cambios.

---

## Cuando NO usar Claude (hacerlo tu mismo)

- Cambiar textos/labels en la GUI → editar `src/gui/app.py` directamente
- Agregar patron de malware → agregar linea en `src/scanners/php_scanner.py` array `PHP_PATTERNS`
- Cambiar config por defecto → editar `src/config/settings.py` dict `DEFAULT_CONFIG`
- Agregar extension escaneable → agregar en `DEFAULT_CONFIG["scan_extensions"]`
