"""Test v2 — multiprocessing + PDF + modos."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

EXTRACT_DIR = r"C:\Users\SSW\AppData\Local\Temp\claude\malclean\scan_ofowkcos"

def log(msg):
    print(msg, flush=True)

def test():
    if not os.path.isdir(EXTRACT_DIR):
        log(f"ERROR: No existe {EXTRACT_DIR}")
        return

    import multiprocessing
    log("=" * 60)
    log(f"TEST cPacleanS v2 — {multiprocessing.cpu_count()} CPUs")
    log("=" * 60)

    from src.core.engine import ScanEngine
    from src.scanners.php_scanner import PHPScanner
    from src.scanners.database_scanner import DatabaseScanner
    from src.scanners.email_scanner import EmailScanner
    from src.scanners.cms_scanner import CMSScanner
    from src.scanners.yara_scanner import YaraScanner

    engine = ScanEngine(progress_callback=lambda t, v: None)
    for cls in [PHPScanner, DatabaseScanner, EmailScanner, CMSScanner, YaraScanner]:
        engine.register_scanner_class(cls)

    t0 = time.time()
    result = engine.scan_directory(EXTRACT_DIR)
    elapsed = time.time() - t0

    log(f"\nArchivos: {result.total_files_scanned}")
    log(f"Amenazas: {result.total_threats_found}")
    log(f"Workers: {result.workers_used}")
    log(f"Duracion: {elapsed:.1f}s")
    log(f"Errores: {len(result.scan_errors)}")
    log(f"Severidad: {result.summary_by_severity}")

    confirmed = sum(1 for f in result.findings if f.confirmed_malware)
    log(f"Confirmados: {confirmed}")
    log(f"Sospechosos: {result.total_threats_found - confirmed}")

    # Test PDF
    log("\n--- Test PDF ---")
    try:
        from src.report.generator import ReportGenerator
        gen = ReportGenerator(r"C:\Users\SSW\Documents\limpiador_malware\reportes")
        html_path = gen.generate(result, "backup-tommysto.tar.gz")
        log(f"HTML: {html_path}")
        pdf_path = gen.generate_pdf(result, "backup-tommysto.tar.gz")
        log(f"PDF: {pdf_path}")
        log(f"PDF size: {os.path.getsize(pdf_path)} bytes")
    except Exception as e:
        log(f"ERROR: {e}")
        import traceback; traceback.print_exc()

    if result.scan_errors:
        log(f"\n--- Errores ({len(result.scan_errors)}) ---")
        for e in result.scan_errors[:5]:
            log(f"  {e}")

    log("\n" + "=" * 60)
    log("TEST COMPLETADO")
    log("=" * 60)

if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    test()
