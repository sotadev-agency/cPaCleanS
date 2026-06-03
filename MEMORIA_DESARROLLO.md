# cPacleanS — Memoria de Desarrollo

Registro de correcciones, mejoras y decisiones tecnicas para referencia en futuras sesiones con Claude.

---

## v2.0.0 (2026-06-01)

### Arquitectura
- Migrado de threading a **multiprocessing** con ProcessPoolExecutor
- Scanners persistentes por proceso worker (evita re-compilar regex por archivo)
- Batch processing: lotes de 50+ archivos por worker para minimizar overhead IPC
- Fallback automatico a threading si multiprocessing falla

### Rendimiento probado
| Backup | Archivos | Tiempo |
|--------|----------|--------|
| 50 MB (tendende) | 3,075 | 58s |
| 354 MB (tommysto) | 22,472 | 35s |
| 1.2 GB (miacarra) | 52,013 | 936s |

### Correcciones criticas
1. **Rutas largas Windows** (>260 chars): prefijo `\\?\` + extraccion tolerante a fallos
2. **Falsos positivos resueltos**:
   - `shell.php` del core WP (`wp-includes/Text/Diff/Engine/`) → excluido via SAFE_DIRS
   - `FileManager.php` de JetBackup → excluido via SAFE_DIRS
   - Archivos Sucuri en uploads → excluidos por prefijo `sucuri-`, `wordfence`, etc.
   - Archivos de Joomla `media/` → solo alerta en `upload_dir` explicito, no en `content_dir`
   - PHP en plugins/temas WP → no marcar como cms_upload_php si esta en core dirs de otro CMS
3. **Clasificacion multi-patron**: archivos con injection+obfuscation+high+3 hits → confirmado
4. **htaccess_redirect** agregado a CONFIRMED_MALWARE_CATEGORIES
5. **PDF encoding error** con backups grandes: `_safe_text()` convierte a latin-1, max 50 filas
6. **Jinja2 truncate_path**: registrado como filter en Environment, no en globals

### Decisiones de diseno
- `suspicious_filename` NO es categoria de cuarentena automatica — requiere verificacion manual
- Solo se mueven a cuarentena archivos con `confirmed_malware=True`
- Copia original SIEMPRE se guarda en `originales_intactos/` antes de mover
- CMS restorer solo restaura plugins/temas **activos** segun la DB del backup

---

## v2.0.1 (2026-06-02)

### Correcciones de usuario (post-prueba con instalador Inno Setup)
1. **UI bloqueada durante escaneo**: `_lock_ui()` / `_unlock_ui()` deshabilita todos los controles
2. **Log por fases**: separadores visuales, solo resultados importantes, no llena de lineas
3. **Escaneo de reinfeccion**: 11 patrones nuevos en correos + 6 en codigo propio
4. **HTML legible**: columna archivo muestra solo nombre, `word-break: break-word`
5. **PDF robusto**: max 50 filas, `_safe_text()`, seccion "Que significa esto" para no-tecnicos
6. **Solo plugins/temas activos**: lee `active_plugins` y `template` del dump SQL
7. **VT API tipos**: modo "confirmar" (rapido, hashes) vs "profundo" (upload archivos)
8. **Nombre archivo salida**: dialogo personalizable antes de empaquetar

### Puntos a mejorar en futuras versiones
- [ ] Escaneo de archivos Python (.py) para hostings con Django/Flask
- [ ] Progreso en tiempo real durante extraccion (actualmente solo al final)
- [ ] Soporte Joomla/Moodle restauracion automatica desde repos oficiales
- [ ] Cache de hashes VirusTotal para evitar re-consultas
- [ ] Modo CLI (sin GUI) para automatizacion / scripts
- [ ] Firmar el ejecutable con certificado de codigo
- [ ] Auto-update desde GitHub releases

---

## v2.1.0 (2026-06-02)

### Bug corregido
- **Nombre del archivo comprimido se truncaba** en backups con puntos en el nombre
  - `backup-6.1.2026_10-12-04_vinculo.tar.gz` generaba `backup-6.tar.gz`
  - Fix: `re.sub(r'\.(tar\.gz|tgz|tar|zip|gz)$', '', name)` en vez de `split(".")[0]`

### Mejoras
1. **Cuarentena de archivos 0KB**: archivos vacios se mueven a `archivos_0kb/` (normal/intermedio) o se eliminan (estricto)
2. **Separar plugins/temas premium y sospechosos**:
   - Premium (no en WordPress.org) → `plugins_temas_separados/premium/`
   - Sospechosos (nombres aleatorios) → `plugins_temas_separados/sospechosos/`
   - No se incluyen en el backup limpio final
3. **Ruta original en reporte HTML**: nueva columna "Ruta" con path relativo desde `homedir/`
   - Formato: `homedir/public_html/wp-content/uploads/shell.php`

### Estructura de cuarentena actualizada
```
cuarentena_FECHA/
  originales_intactos/     ← copias de seguridad
  amenazas_removidas/      ← malware extraido
  archivos_0kb/            ← archivos vacios
  plugins_temas_separados/
    premium/               ← pedir al desarrollador
    sospechosos/           ← NO resubir
```
