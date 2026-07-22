"""Integración con VirusTotal API v3 — escaneo de hashes y archivos sospechosos."""
import hashlib
import time
import requests
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class VTResult:
    file_path: str
    sha256: str
    detected: bool = False
    detection_count: int = 0
    total_engines: int = 0
    detections: list = field(default_factory=list)
    permalink: str = ""
    error: str = ""


VT_BASE = "https://www.virustotal.com/api/v3"
RATE_LIMIT_DELAY = 15


class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}
        self._last_request = 0

    def _rate_limit(self):
        now = time.time()
        elapsed = now - self._last_request
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)
        self._last_request = time.time()

    def check_hash(self, file_path: str) -> VTResult:
        sha256 = self._compute_hash(file_path)
        result = VTResult(file_path=file_path, sha256=sha256)

        if not self.api_key:
            result.error = "No API key configured"
            return result

        self._rate_limit()

        try:
            resp = requests.get(
                f"{VT_BASE}/files/{sha256}",
                headers=self.headers,
                timeout=30,
            )

            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                result.detection_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
                result.total_engines = sum(stats.values())
                result.detected = result.detection_count > 0
                result.permalink = f"https://www.virustotal.com/gui/file/{sha256}"

                results_detail = attrs.get("last_analysis_results", {})
                for engine, info in results_detail.items():
                    if info.get("category") in ("malicious", "suspicious"):
                        result.detections.append({
                            "engine": engine,
                            "result": info.get("result", ""),
                            "category": info.get("category", ""),
                        })

            elif resp.status_code == 404:
                pass
            else:
                result.error = f"HTTP {resp.status_code}"

        except requests.RequestException as e:
            result.error = str(e)

        return result

    def upload_and_scan(self, file_path: str) -> VTResult:
        sha256 = self._compute_hash(file_path)
        result = VTResult(file_path=file_path, sha256=sha256)

        if not self.api_key:
            result.error = "No API key configured"
            return result

        file_size = Path(file_path).stat().st_size
        if file_size > 32 * 1024 * 1024:
            result.error = "Archivo demasiado grande para upload (>32MB)"
            return result

        self._rate_limit()

        try:
            with open(file_path, "rb") as f:
                resp = requests.post(
                    f"{VT_BASE}/files",
                    headers=self.headers,
                    files={"file": (Path(file_path).name, f)},
                    timeout=120,
                )

            if resp.status_code == 200:
                analysis_id = resp.json().get("data", {}).get("id", "")
                if analysis_id:
                    result = self._poll_analysis(analysis_id, file_path, sha256)
            else:
                result.error = f"Upload error: HTTP {resp.status_code}"

        except requests.RequestException as e:
            result.error = str(e)

        return result

    def _poll_analysis(self, analysis_id: str, file_path: str, sha256: str) -> VTResult:
        result = VTResult(file_path=file_path, sha256=sha256)

        for _ in range(12):
            time.sleep(RATE_LIMIT_DELAY)
            try:
                resp = requests.get(
                    f"{VT_BASE}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=30,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    if data.get("status") == "completed":
                        stats = data.get("stats", {})
                        result.detection_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
                        result.total_engines = sum(stats.values())
                        result.detected = result.detection_count > 0
                        result.permalink = f"https://www.virustotal.com/gui/file/{sha256}"
                        return result
            except requests.RequestException:
                pass

        result.error = "Timeout esperando resultado de análisis"
        return result

    def batch_check(self, file_paths: list, progress_callback=None) -> list:
        results = []
        total = len(file_paths)
        for i, fp in enumerate(file_paths):
            vt = self.check_hash(fp)
            results.append(vt)
            if progress_callback:
                progress_callback("vt_progress", int((i + 1) / total * 100))
        return results

    @staticmethod
    def _compute_hash(file_path: str) -> str:
        sha = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha.update(chunk)
        return sha.hexdigest()
