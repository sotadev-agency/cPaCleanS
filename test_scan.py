"""Test completo contra el backup real — captura todos los errores."""
import sys
import os
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BACKUP = r"C:\Users\SSW\Documents\limpiador_malware\backup-tommysto.tar.gz"

def log(msg):
    print(msg, flush=True)

def test():
    # Fase 1: Extracción
    log("=" * 60)
    log("FASE 1: Extracción del backup")
    log("=" * 60)
    try:
        from src.core.extractor import BackupExtractor
        ext = BackupExtractor(BACKUP, progress_callback=lambda t, v: None)
        info = ext.extract()
        log(f"  OK - Extraído en: {info.extract_dir}")
        log(f"  Archivos: {info.total_files}")
        log(f"  Tamaño: {info.total_size_mb} MB")
        log(f"  Usuario cPanel: {info.cpanel_user}")
        log(f"  MySQL: {info.has_mysql}")
        log(f"  Email: {info.has_email}")
        log(f"  HomeDIR: {info.has_homedir}")
        log(f"  CMS: {info.cms_detected}")
        log(f"  DBs: {len(info.structure.get('databases', []))}")
        log(f"  Emails: {len(info.structure.get('emails', []))}")
        log(f"  Websites: {len(info.structure.get('websites', []))}")
    except Exception as e:
        log(f"  ERROR extracción: {e}")
        traceback.print_exc()
        return

    # Fase 2: Escaneo con cada scanner individual
    log("\n" + "=" * 60)
    log("FASE 2: Test de cada scanner individual")
    log("=" * 60)

    from src.core.engine import ScanEngine
    from src.scanners.php_scanner import PHPScanner
    from src.scanners.database_scanner import DatabaseScanner
    from src.scanners.email_scanner import EmailScanner
    from src.scanners.cms_scanner import CMSScanner
    from src.scanners.yara_scanner import YaraScanner

    scanners = [
        ("PHPScanner", PHPScanner()),
        ("DatabaseScanner", DatabaseScanner()),
        ("EmailScanner", EmailScanner()),
        ("CMSScanner", CMSScanner()),
        ("YaraScanner", YaraScanner()),
    ]

    # Recoger todos los archivos
    all_files = []
    for root, dirs, files in os.walk(info.extract_dir):
        for f in files:
            all_files.append(os.path.join(root, f))

    log(f"  Total archivos encontrados: {len(all_files)}")

    for name, scanner in scanners:
        log(f"\n  --- {name} ---")
        findings = []
        errors = []
        for fp in all_files:
            try:
                result = scanner.scan(fp)
                if result:
                    findings.extend(result)
            except Exception as e:
                errors.append((fp, str(e)))

        log(f"    Hallazgos: {len(findings)}")
        log(f"    Errores: {len(errors)}")
        if errors:
            for fp, err in errors[:5]:
                log(f"      ERROR en {os.path.basename(fp)}: {err}")
        if findings:
            by_sev = {}
            for f in findings:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            log(f"    Por severidad: {by_sev}")
            for f in findings[:3]:
                log(f"    Ejemplo: [{f.severity}] {f.category} - {f.description}")
                log(f"             {os.path.basename(f.file_path)}:{f.line_number}")

    # Fase 3: Motor completo
    log("\n" + "=" * 60)
    log("FASE 3: Motor de escaneo completo")
    log("=" * 60)
    try:
        engine = ScanEngine(progress_callback=lambda t, v: None)
        for _, scanner in scanners:
            engine.register_scanner(scanner)
        result = engine.scan_directory(info.extract_dir, backup_info=info)
        log(f"  Archivos escaneados: {result.total_files_scanned}")
        log(f"  Amenazas: {result.total_threats_found}")
        log(f"  Duración: {result.scan_duration_seconds}s")
        log(f"  Por severidad: {result.summary_by_severity}")
        log(f"  Por categoría: {result.summary_by_category}")
    except Exception as e:
        log(f"  ERROR motor: {e}")
        traceback.print_exc()
        return

    # Fase 4: Generador de reporte
    log("\n" + "=" * 60)
    log("FASE 4: Generación de reporte")
    log("=" * 60)
    try:
        from src.report.generator import ReportGenerator
        gen = ReportGenerator(os.path.join(os.path.dirname(BACKUP), "reportes"))
        report_path = gen.generate(result, BACKUP)
        log(f"  Reporte generado: {report_path}")
    except Exception as e:
        log(f"  ERROR reporte: {e}")
        traceback.print_exc()

    log("\n" + "=" * 60)
    log("TEST COMPLETADO")
    log("=" * 60)


if __name__ == "__main__":
    test()
