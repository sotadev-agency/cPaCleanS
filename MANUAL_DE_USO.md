# cPacleanS v2.0.0 — Manual de Uso

## Que es cPacleanS

Herramienta de escritorio para Windows que escanea y limpia malware en copias de seguridad generadas desde cPanel. Soporta WordPress, Moodle, Joomla, Laravel y codigo PHP/HTML/JS/CSS propio.

---

## Instalacion

1. Ejecutar `cPacleanS_Setup_v2.0.0.exe`
2. Seguir el asistente de instalacion
3. Abrir desde el acceso directo en el escritorio o menu inicio

**Requisito**: Windows 10/11 64-bit

---

## Uso rapido (3 pasos)

### Paso 1 — Seleccionar backup
- Click en **Explorar** y seleccionar el archivo `.tar.gz` descargado de cPanel
- Formatos soportados: `.tar.gz`, `.tgz`, `.zip`, `.gz`, `.tar`

### Paso 2 — Elegir modo

| Modo | Que hace | Cuando usarlo |
|------|----------|---------------|
| **Solo Escaneo** | Genera reporte sin tocar archivos | Diagnostico inicial, auditorias |
| **Normal** | Solo malware confirmado a cuarentena | Uso recomendado, seguro |
| **Intermedio** | Confirmados + alta severidad a cuarentena | Cuentas con mucha infeccion |
| **Estricto** | TODO lo sospechoso eliminado | Ultima opcion, mas agresivo |

### Paso 3 — Click en INICIAR

La app ejecuta automaticamente:
1. Extraccion del backup
2. Escaneo multiprocessing (usa todos los CPUs)
3. Consulta VirusTotal (si hay API key configurada)
4. Restauracion de CMS desde repos oficiales (si esta activado)
5. Limpieza segun el modo seleccionado
6. Generacion de reporte HTML + PDF

---

## Opciones adicionales

### Restaurar CMS desde repos oficiales
- Checkbox activo por defecto
- Descarga WordPress/plugins/temas limpios desde wordpress.org
- Reemplaza archivos core modificados por versiones originales
- Temas/plugins premium que no estan en el repo se reportan como no verificables

### Generar PDF para cliente
- Checkbox activo por defecto
- Crea un PDF resumen profesional con:
  - Resumen ejecutivo
  - Severidades y categorias
  - Top hallazgos
  - Log de restauracion CMS

### Post-limpieza
Al terminar la limpieza, la app pregunta:
- **SI** = Generar `.tar.gz` listo para importar en cPanel
- **NO** = Copiar archivos limpios a una carpeta local
- **CANCELAR** = Solo dejar los reportes

---

## Configuracion (boton Config)

| Campo | Descripcion | Valor por defecto |
|-------|-------------|-------------------|
| VirusTotal API Key | Key gratuita de virustotal.com | Vacio (opcional) |
| Tamano maximo archivo | No escanear archivos mas grandes | 50 MB |
| Workers de escaneo | CPUs a utilizar (slider) | CPUs - 1 |
| Restaurar CMS core | Activar restauracion automatica | Si |

### Obtener API key de VirusTotal (gratis)
1. Registrarse en https://www.virustotal.com
2. Ir a perfil > API key
3. Copiar y pegar en Config

---

## Cuarentena segura

- Los archivos limpios SIEMPRE se respaldan antes de mover
- Carpeta `cuarentena_FECHA/originales_intactos/` = copias sin alterar
- Carpeta `cuarentena_FECHA/amenazas_removidas/` = archivos extraidos
- En modo **Normal**, solo se mueven archivos con malware confirmado (webshells, backdoors, cryptominers)
- Los sospechosos se **reportan pero NO se tocan**

---

## Que detecta

| Categoria | Ejemplos |
|-----------|----------|
| WebShells | C99, R57, WSO, b374k, FilesMan |
| Backdoors | eval+base64, system+$_POST, proc_open |
| Inyecciones PHP | eval, assert, preg_replace /e, create_function |
| Ofuscacion | chr() encadenados, hex strings, gz+base64 |
| DB MySQL | PHP embebido en SQL, XSS almacenado, usuarios admin falsos |
| Email | Phishing, adjuntos .exe/.php, URLs con IP directa |
| CMS | PHP en uploads, .htaccess malicioso, plugins vulnerables |
| JavaScript | Crypto-miners, eval+atob, scripts externos maliciosos |
| .htaccess | Redirecciones SEO spam, handlers PHP en imagenes |

---

## Reportes

Se generan en la carpeta `reportes/` junto al backup:

- **HTML** — Reporte interactivo completo con todos los hallazgos, codigo contexto, graficas de severidad
- **PDF** — Resumen ejecutivo para entregar al cliente

---

## Rendimiento estimado

| Tamano backup | Archivos | Tiempo aprox. (4 CPUs) |
|---------------|----------|------------------------|
| 50 MB | ~3,000 | ~1 minuto |
| 350 MB | ~22,000 | ~8 minutos |
| 1.2 GB | ~52,000 | ~20 minutos |

---

## Soporte

- Repositorio: https://github.com/sotadev-agency/proyectos-ia.git
- Reportar fallas: ver `GUIA_REPORTAR_FALLAS.md`
