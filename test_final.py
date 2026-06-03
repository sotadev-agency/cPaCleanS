"""Test final — pipeline completa contra todos los backups infectados."""
import sys, os, time, traceback, multiprocessing
sys.stdout.reconfigure(line_buffering=True)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BACKUP_DIR = r"C:\Users\SSW\Documents\limpiador_malware\backups-malware"

def log(msg):
    print(msg, flush=True)

def test_one_backup(backup_path):
    log(f"\n{'='*70}")
    log(f"  BACKUP: {os.path.basename(backup_path)}")
    log(f"  Size: {round(os.path.getsize(backup_path)/1024/1024, 1)} MB")
    log(f"{'='*70}")

    errors = []

    # FASE 1: Extracción
    log("\n[1] Extraccion...")
    t0 = time.time()
    try:
        from src.core.extractor import BackupExtractor
        ext = BackupExtractor(backup_path, progress_callback=lambda t,v: None)
        info = ext.extract()
        log(f"    OK en {round(time.time()-t0,1)}s")
        log(f"    Dir: {info.extract_dir}")
        log(f"    Archivos: {info.total_files} | {info.total_size_mb} MB")
        log(f"    User: {info.cpanel_user}")
        log(f"    MySQL: {info.has_mysql} | Email: {info.has_email} | Home: {info.has_homedir}")
        log(f"    CMS: {info.cms_detected}")
        log(f"    DBs: {len(info.structure.get('databases',[]))} | Emails: {len(info.structure.get('emails',[]))}")
        if info.extraction_errors:
            log(f"    Warnings extraccion: {len(info.extraction_errors)}")
            for e in info.extraction_errors[:3]:
                log(f"      {e[:120]}")
    except Exception as e:
        log(f"    ERROR: {e}")
        traceback.print_exc()
        errors.append(("extraccion", str(e)))
        return errors

    # FASE 2: Escaneo multiprocessing
    log("\n[2] Escaneo multiprocessing...")
    t0 = time.time()
    try:
        from src.core.engine import ScanEngine
        from src.scanners.php_scanner import PHPScanner
        from src.scanners.database_scanner import DatabaseScanner
        from src.scanners.email_scanner import EmailScanner
        from src.scanners.cms_scanner import CMSScanner
        from src.scanners.yara_scanner import YaraScanner

        engine = ScanEngine(progress_callback=lambda t,v: None)
        for cls in [PHPScanner, DatabaseScanner, EmailScanner, CMSScanner, YaraScanner]:
            engine.register_scanner_class(cls)

        result = engine.scan_directory(info.extract_dir, backup_info=info)
        elapsed = round(time.time()-t0, 1)

        confirmed = sum(1 for f in result.findings if f.confirmed_malware)
        suspect = result.total_threats_found - confirmed

        log(f"    OK en {elapsed}s | Workers: {result.workers_used}")
        log(f"    Archivos escaneados: {result.total_files_scanned}")
        log(f"    Amenazas: {result.total_threats_found}")
        log(f"    CONFIRMADOS: {confirmed} | Sospechosos: {suspect}")
        log(f"    Severidad: {result.summary_by_severity}")
        log(f"    Categorias: {result.summary_by_category}")
        if result.scan_errors:
            log(f"    Errores scan: {len(result.scan_errors)}")
            for e in result.scan_errors[:5]:
                log(f"      {e[:120]}")
    except Exception as e:
        log(f"    ERROR: {e}")
        traceback.print_exc()
        errors.append(("escaneo", str(e)))
        return errors

    # FASE 3: Reporte HTML
    log("\n[3] Reporte HTML...")
    try:
        from src.report.generator import ReportGenerator
        gen = ReportGenerator(os.path.join(BACKUP_DIR, "reportes"))
        html_path = gen.generate(result, backup_path)
        html_size = round(os.path.getsize(html_path)/1024, 1)
        log(f"    OK: {html_path} ({html_size} KB)")
    except Exception as e:
        log(f"    ERROR: {e}")
        traceback.print_exc()
        errors.append(("reporte_html", str(e)))

    # FASE 4: Reporte PDF
    log("\n[4] Reporte PDF...")
    try:
        pdf_path = gen.generate_pdf(result, backup_path)
        pdf_size = round(os.path.getsize(pdf_path)/1024, 1)
        log(f"    OK: {pdf_path} ({pdf_size} KB)")
    except Exception as e:
        log(f"    ERROR: {e}")
        traceback.print_exc()
        errors.append(("reporte_pdf", str(e)))

    # FASE 5: Limpieza modo normal (dry-run info)
    log("\n[5] Limpieza info...")
    try:
        log(f"    Normal:      {sum(1 for f in result.findings if f.confirmed_malware)} archivos")
        log(f"    Intermedio:  {sum(1 for f in result.findings if f.confirmed_malware or f.severity in ('critical','high'))} archivos")
        log(f"    Estricto:    {result.total_threats_found} archivos")
    except Exception as e:
        errors.append(("limpieza_info", str(e)))

    # FASE 6: CMS Restorer info
    log("\n[6] CMS Restorer info...")
    try:
        if info.cms_detected:
            from src.core.cms_restorer import CMSRestorer
            restorer = CMSRestorer(info.extract_dir, progress_callback=lambda t,v: None)
            # Solo detectar versiones, no descargar
            for cms in info.cms_detected:
                if cms == "wordpress":
                    roots = restorer._find_wp_roots()
                    for r in roots:
                        ver = restorer._detect_wp_version(r)
                        log(f"    WordPress {ver} en {str(r)[-60:]}")
                elif cms == "moodle":
                    log(f"    Moodle detectado")
        else:
            log(f"    No CMS detectados")
    except Exception as e:
        log(f"    ERROR: {e}")
        traceback.print_exc()
        errors.append(("cms_restorer", str(e)))

    # FASE 7: Top hallazgos
    log("\n[7] Top 10 hallazgos:")
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_f = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 5))
    for f in sorted_f[:10]:
        tipo = "CONF" if f.confirmed_malware else "sosp"
        fname = os.path.basename(f.file_path)
        log(f"    [{f.severity:8s}] [{tipo}] {f.category:25s} | {fname}:{f.line_number} | {f.description[:60]}")

    # Cleanup
    try:
        ext.cleanup()
        log("\n    Cleanup OK")
    except Exception:
        pass

    return errors


def main():
    log("=" * 70)
    log(f"  cPacleanS v2 — Test Final Completo")
    log(f"  CPUs: {multiprocessing.cpu_count()}")
    log("=" * 70)

    backups = []
    for f in sorted(os.listdir(BACKUP_DIR)):
        fp = os.path.join(BACKUP_DIR, f)
        if os.path.isfile(fp) and (f.endswith('.tar.gz') or f.endswith('.zip') or f.endswith('.tgz')):
            backups.append(fp)

    log(f"\nBackups encontrados: {len(backups)}")
    for b in backups:
        log(f"  - {os.path.basename(b)} ({round(os.path.getsize(b)/1024/1024,1)} MB)")

    all_errors = {}
    t_total = time.time()

    for bp in backups:
        errs = test_one_backup(bp)
        if errs:
            all_errors[os.path.basename(bp)] = errs

    elapsed_total = round(time.time() - t_total, 1)

    log(f"\n{'='*70}")
    log(f"  RESUMEN FINAL — {elapsed_total}s total")
    log(f"{'='*70}")
    log(f"  Backups procesados: {len(backups)}")

    if all_errors:
        log(f"  ERRORES:")
        for name, errs in all_errors.items():
            for phase, err in errs:
                log(f"    {name} [{phase}]: {err[:100]}")
    else:
        log(f"  SIN ERRORES en ninguna fase")

    log(f"\n{'='*70}")
    log(f"  TEST COMPLETADO")
    log(f"{'='*70}")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
