from pathlib import Path
from datetime import datetime, timezone
import json
import re

from analyzer.config import Settings
from analyzer.utils import sha256_file, sha1_file, md5_file, run_cmd
from analyzer.virustotal import VirusTotalClient
import shlex

class AnalysisEngine:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.vt = VirusTotalClient(settings.vt_api_key)

    def analyze(self, path: Path, job_id: str, allow_vt_upload: bool = False) -> dict:
        # If a directory is provided, run a recursive analysis and return an aggregated report
        if path.is_dir():
            files = []
            for p in sorted(path.rglob("*")):
                if p.is_file():
                    try:
                        files.append(self._analyze_file(p, job_id, allow_vt_upload))
                    except Exception:
                        # Continue on per-file errors
                        continue

            report = {
                "schema": "station-blanche-bulk-report-v1",
                "job_id": job_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": str(path),
                "file_count": len(files),
                "files": files,
                "local": {},
            }

            # If configured, run rkhunter (or another volume-level scanner) once for the entire path
            if self.settings.rkhunter_cmd:
                try:
                    cmd_template = self.settings.rkhunter_cmd
                    rendered = cmd_template.format(path=str(path))
                    cmd_list = shlex.split(rendered)
                    report["local"]["rkhunter"] = run_cmd(cmd_list, timeout=self.settings.command_timeout)
                except Exception as e:
                    report["local"]["rkhunter"] = {"cmd": [self.settings.rkhunter_cmd], "returncode": -2, "stdout": "", "stderr": str(e)}

            return report

        return self._analyze_file(path, job_id, allow_vt_upload)

    def _analyze_file(self, path: Path, job_id: str, allow_vt_upload: bool = False) -> dict:
        sha256 = sha256_file(path)
        report = {
            "schema": "station-blanche-report-v1",
            "job_id": job_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "filename": path.name,
            "path": str(path),
            "size": path.stat().st_size,
            "hashes": {
                "md5": md5_file(path),
                "sha1": sha1_file(path),
                "sha256": sha256,
            },
            "local": {},
            "virustotal": {
                "enabled": self.vt.enabled,
                "known": None,
                "uploaded": False,
                "stats": None,
                "error": None,
            },
            "verdict": "sain",
            "reasons": [],
        }

        report["local"]["file"] = run_cmd(["file", "--brief", str(path)], timeout=self.settings.command_timeout)
        report["local"]["file_mime"] = run_cmd(["file", "--mime", str(path)], timeout=self.settings.command_timeout)
        report["local"]["clamav"] = run_cmd(["clamscan", "--infected", "--no-summary", "--alert-encrypted", str(path)], timeout=180)
        report["local"]["exiftool"] = run_cmd(["exiftool", "-json", str(path)], timeout=self.settings.command_timeout)
        report["local"]["strings"] = run_cmd(["strings", "-a", "-n", "8", str(path)], timeout=self.settings.command_timeout, max_stdout=30000)

        # Scanner YARA - simple et direct
        yara_rules_dir = self.settings.rules_dir / "malware"
        if yara_rules_dir.exists():
            report["local"]["yara"] = run_cmd(["yara", "-r", str(yara_rules_dir), str(path)], timeout=180)
        else:
            report["local"]["yara"] = {"cmd": ["yara"], "returncode": 0, "stdout": "", "stderr": "Dossier malware absent"}

        # Secondary scanner (configurable)
        if self.settings.extra_scanner_cmd:
            try:
                cmd_template = self.settings.extra_scanner_cmd
                rendered = cmd_template.format(path=str(path))
                cmd_list = shlex.split(rendered)
                report["local"]["extra_scanner"] = run_cmd(cmd_list, timeout=self.settings.command_timeout)
                report["local"]["extra_scanner"]["name"] = self.settings.extra_scanner_name or "extra_scanner"
            except Exception as e:
                report["local"]["extra_scanner"] = {"cmd": [self.settings.extra_scanner_cmd], "returncode": -2, "stdout": "", "stderr": str(e)}

        vt_report = self.vt.get_file_report(sha256)
        report["virustotal"].update(vt_report)

        if vt_report.get("known") is False and allow_vt_upload and self.settings.vt_enable_upload:
            upload = self.vt.upload_file(path)
            report["virustotal"].update(upload)

        self._apply_verdict(report)
        return report

    def _apply_verdict(self, report: dict):
        reasons = report["reasons"]
        verdict = "sain"

        clam = report["local"].get("clamav", {})
        if clam.get("returncode") == 1:
            verdict = "malveillant"
            reasons.append("Détection ClamAV")

        yara = report["local"].get("yara", {})
        if yara.get("stdout", "").strip():
            verdict = "malveillant"
            reasons.append("Correspondance YARA")

        vt = report.get("virustotal", {})
        stats = vt.get("stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        if malicious >= self.settings.vt_malicious_threshold:
            verdict = "malveillant"
            reasons.append(f"VirusTotal : {malicious} moteurs malveillants")
        elif verdict != "malveillant" and (malicious >= self.settings.vt_suspicious_threshold or suspicious > 0):
            verdict = "suspect"
            reasons.append(f"VirusTotal : malicious={malicious}, suspicious={suspicious}")

        file_out = (report["local"].get("file", {}).get("stdout") or "").lower()
        strings_out = (report["local"].get("strings", {}).get("stdout") or "").lower()
        suspicious_markers = [
            "powershell", "cmd.exe", "wscript", "cscript", "javascript", "macro",
            "autoopen", "document_open", "pe32", "executable", "elf", "macho",
            "base64", "frombase64string", "invoke-expression", "rundll32",
            "regsvr32", "mshta", "encrypted", "password protected"
        ]
        if verdict != "malveillant":
            for marker in suspicious_markers:
                if marker in file_out or marker in strings_out:
                    verdict = "suspect"
                    reasons.append(f"Indicateur local suspect : {marker}")
                    break

        report["verdict"] = verdict
