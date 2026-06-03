"""Test rápido contra la extracción existente."""
import sys, os, time, traceback
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

EXTRACT_DIR = r"C:\Users\SSW\AppData\Local\Temp\claude\malclean\scan_ofowkcos"

def log(msg):
    print(msg, flush=True)

def test():
    if not os.path.isdir(EXTRACT_DIR):
        log(f"ERROR: No existe {EXTRACT_DIR}")
        return

    from src.core.engine import ScanEngine
    from src.scanners.php_scanner import PHPScanner
    from src.scanners.database_scanner import DatabaseScanner
    from src.scanners.email_scanner import EmailScanner
    from src.scanners.cms_scanner import CMSScanner
    from src.scanners.yara_scanner import YaraScanner

    log("=" * 60)
    log("TEST con extraccion existente")
    log("=" * 60)

    engine = ScanEngine(progress_callback=lambda t, v: log(f"  [{t}] {v}") if t == "status" else None)
    engine.register_scanner(PHPScanner())
    engine.register_scanner(DatabaseScanner())
    engine.register_scanner(EmailScanner())
    engine.register_scanner(CMSScanner())
    engine.register_scanner(YaraScanner())

    try:
        result = engine.scan_directory(EXTRACT_DIR)
    except Exception as e:
        log(f"ERROR: {e}")
        traceback.print_exc()
        return

    log(f"\nArchivos escaneados: {result.total_files_scanned}")
    log(f"Amenazas: {result.total_threats_found}")
    log(f"Duracion: {result.scan_duration_seconds}s")
    log(f"Errores: {len(result.scan_errors)}")
    log(f"Por severidad: {result.summary_by_severity}")
    log(f"Por categoria: {result.summary_by_category}")

    confirmed = [f for f in result.findings if f.confirmed_malware]
    suspect = [f for f in result.findings if not f.confirmed_malware]
    log(f"\nCONFIRMADOS para cuarentena: {len(confirmed)}")
    log(f"Sospechosos (no tocar): {len(suspect)}")

    log("\n--- Top hallazgos CONFIRMADOS ---")
    for f in confirmed[:20]:
        short = os.path.basename(f.file_path)
        log(f"  [{f.severity}] {f.category} | {short}:{f.line_number} | {f.description}")

    log("\n--- Top hallazgos Sospechosos ---")
    for f in suspect[:15]:
        short = os.path.basename(f.file_path)
        log(f"  [{f.severity}] {f.category} | {short}:{f.line_number} | {f.description}")

    if result.scan_errors:
        log(f"\n--- Errores ({len(result.scan_errors)}) ---")
        for e in result.scan_errors[:10]:
            log(f"  {e}")

    # Test reporte
    log("\n--- Test Reporte ---")
    try:
        from src.report.generator import ReportGenerator
        gen = ReportGenerator(r"C:\Users\SSW\Documents\limpiador_malware\reportes")
        rpath = gen.generate(result, "backup-tommysto.tar.gz")
        log(f"Reporte: {rpath}")
    except Exception as e:
        log(f"ERROR reporte: {e}")
        traceback.print_exc()

    # Test cuarentena
    log("\n--- Test Cuarentena (solo info, no ejecuta) ---")
    log(f"Se pondrian en cuarentena: {len(confirmed)} archivos")
    log(f"Se dejarian intactos: {len(suspect)} archivos sospechosos")

    log("\n" + "=" * 60)
    log("TEST COMPLETADO")
    log("=" * 60)


if __name__ == "__main__":
    test()
