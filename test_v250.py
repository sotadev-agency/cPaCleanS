import tempfile, os, tarfile, shutil, time, sys, multiprocessing, base64
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Encoded payloads for test (avoid AV)
P = {}
P["shell"] = base64.b64decode("PD9waHAgZXZhbChiYXNlNjRfZGVjb2RlKCRfUE9TVFsiY21kIl0pKTsgPz4=").decode()
P["dblext"] = base64.b64decode("PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOyA/Pg==").decode()
P["backdoor"] = base64.b64decode("PD9waHAgJHg9ImJhc2U2NF9kZWNvZGUiOyBldmFsKCR4KCJjM2x6ZEdWdCIpKTsgPz4=").decode()
P["hijack"] = base64.b64decode("PD9waHAgZXZhbChiYXNlNjRfZGVjb2RlKCJkR1Z6ZEE9PSIpKTsgPz4=").decode()
P["htaccess"] = base64.b64decode("QWRkSGFuZGxlciBhcHBsaWNhdGlvbi94LWh0dHBkLXBocCAuanBnIC5naWYgLnBuZw==").decode()
P["wpconfig"] = base64.b64decode("PD9waHAKZGVmaW5lKCJEQl9OQU1FIiwgInRlc3RkYiIpOwokdGFibGVfcHJlZml4ID0gIndwXyI7Cg==").decode()
P["versionphp"] = base64.b64decode("PD9waHAKJHdwX3ZlcnNpb24gPSAiNi40LjIiOwo=").decode()
P["akismet"] = base64.b64decode("PD9waHAKLyogUGx1Z2luIE5hbWU6IEFraXNtZXQgKi8KZnVuY3Rpb24gYWtpc21ldF9jaGVjaygpIHsgcmV0dXJuIHRydWU7IH0K").decode()
P["style"] = base64.b64decode("LyogVGhlbWUgTmFtZTogVHdlbnR5IFR3ZW50eS1Gb3VyICovCmJvZHkgeyBtYXJnaW46IDA7IH0K").decode()
P["sqlinject"] = base64.b64decode("SU5TRVJUIElOVE8gd3BfcG9zdHMgVkFMVUVTICgxLCAidGVzdCIsICI8c2NyaXB0PmV2YWwoYXRvYih4KSk8L3NjcmlwdD4iKTs=").decode()

def log(msg): print(msg, flush=True)


def create_backup(tmpdir):
    import io
    files = {
        "backup-test/homedir/public_html/wp-config.php": P["wpconfig"],
        "backup-test/homedir/public_html/wp-includes/version.php": P["versionphp"],
        "backup-test/homedir/public_html/shell_test.php": P["shell"],
        "backup-test/homedir/public_html/wp-content/uploads/2024/01/image.jpg.php": P["dblext"],
        "backup-test/homedir/public_html/wp-config-backup.php": P["backdoor"],
        "backup-test/homedir/public_html/wp-content/plugins/akismet/akismet.php": P["akismet"],
        "backup-test/homedir/public_html/wp-content/themes/twentytwentyfour/style.css": P["style"],
        "backup-test/homedir/public_html/wp-content/uploads/.htaccess": P["htaccess"],
        "backup-test/homedir/public_html/wp-content/uploads/2024/index.php": P["hijack"],
        "backup-test/mysql/testdb.sql": "-- MySQL dump\nCREATE TABLE wp_options (option_id bigint);\n" + P["sqlinject"] + "\n",
    }
    bp = os.path.join(tmpdir, "test-backup.tar.gz")
    with tarfile.open(bp, "w:gz") as tar:
        for arcname, content in files.items():
            data = content.encode("utf-8")
            ti = tarfile.TarInfo(name=arcname)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    return bp

def main():
    log("=" * 60)
    log("  cPacleanS v2.5.0 Pipeline Test")
    log("=" * 60)
    td = tempfile.mkdtemp(prefix="cpac_")
    ok = True
    try:
        bp = create_backup(td)
        log(f"Backup: {round(os.path.getsize(bp)/1024, 1)} KB")
        log("[1] Extract...")
        from src.core.extractor import BackupExtractor
        ext = BackupExtractor(bp, progress_callback=lambda t,v: None)
        info = ext.extract()
        log(f"    {info.total_files} files, CMS: {info.cms_detected}")
        log("[2] Scan...")
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
        confirmed = sum(1 for f in result.findings if f.confirmed_malware)
        log(f"    Files: {result.total_files_scanned} | Threats: {result.total_threats_found} | Confirmed: {confirmed}")
        for f in sorted(result.findings, key=lambda x: -x.confidence_score):
            t = "CONF" if f.confirmed_malware else "sosp"
            log(f"    [{f.severity:8s}] [{t}] s={f.confidence_score:3d} | {f.category:25s} | {os.path.basename(f.file_path)}:{f.line_number}")
        assert result.total_threats_found > 0
        log("[3] Reports...")
        from src.report.generator import ReportGenerator
        gen = ReportGenerator(os.path.join(td, "rep"))
        html = gen.generate(result, bp)
        pdf = gen.generate_pdf(result, bp)
        log(f"    HTML: {round(os.path.getsize(html)/1024,1)}KB, PDF: {round(os.path.getsize(pdf)/1024,1)}KB")
        with open(html, "r", encoding="utf-8") as fh:
            assert "Score" in fh.read()
        log("    Score column OK")
        log("[4] Clean...")
        from src.config.settings import CLEAN_MODE_NORMAL
        cleaned = engine.clean_findings(td, mode=CLEAN_MODE_NORMAL)
        log(f"    Quarantined: {cleaned}")
        log("[5] Cache...")
        from src.utils.hash_cache import HashCache
        s = HashCache().stats()
        log(f"    {s['count']} entries")
        try: ext.cleanup()
        except: pass
    except Exception as e:
        log(f"ERROR: {e}")
        import traceback; traceback.print_exc()
        ok = False
    finally:
        shutil.rmtree(td, ignore_errors=True)
    log("=" * 60)
    log("ALL PASSED" if ok else "FAILED")
    log("=" * 60)
    return ok

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(0 if main() else 1)
