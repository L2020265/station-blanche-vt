from dataclasses import dataclass
from pathlib import Path
import os

@dataclass
class Settings:
    base_dir: Path
    jobs_dir: Path
    reports_dir: Path
    quarantine_dir: Path
    rules_dir: Path
    tmp_dir: Path
    events_log: Path
    vt_api_key: str | None
    vt_enable_upload: bool
    vt_malicious_threshold: int
    vt_suspicious_threshold: int
    max_upload_size: int
    delete_jobs_after_analysis: bool
    command_timeout: int

    #A COMPLETER AJOUT D'UN SCANNER
    # Optional secondary scanner command. Use `{path}` as placeholder for the target path.
    extra_scanner_cmd: str | None
    # Friendly name for the secondary scanner (display in UI).
    extra_scanner_name: str | None
    # Optional rkhunter command to run against a mounted path/volume during directory scans.
    rkhunter_cmd: str | None
    # Allow destructive actions (delete/format). Disabled by default.
    allow_destructive_actions: bool
    # Optional format command. Use `{path}` as placeholder for the device/volume.
    format_cmd: str | None

    @staticmethod
    def from_env():
        base = Path(os.environ.get("SB_BASE_DIR", "/srv/station-blanche"))
        return Settings(
            base_dir=base,
            jobs_dir=Path(os.environ.get("SB_JOBS_DIR", str(base / "jobs"))),
            reports_dir=Path(os.environ.get("SB_REPORTS_DIR", str(base / "reports"))),
            quarantine_dir=Path(os.environ.get("SB_QUARANTINE_DIR", str(base / "quarantine"))),
            rules_dir=Path(os.environ.get("SB_RULES_DIR", str(base / "rules"))),
            tmp_dir=Path(os.environ.get("SB_TMP_DIR", str(base / "tmp"))),
            events_log=Path(os.environ.get("SB_EVENTS_LOG", "/var/log/station-blanche/events.jsonl")),
            vt_api_key=os.environ.get("VT_API_KEY"),
            vt_enable_upload=os.environ.get("VT_ENABLE_UPLOAD", "false").lower() in ("1", "true", "yes", "on"),
            vt_malicious_threshold=int(os.environ.get("VT_MALICIOUS_THRESHOLD", "5")),
            vt_suspicious_threshold=int(os.environ.get("VT_SUSPICIOUS_THRESHOLD", "1")),
            max_upload_size=int(os.environ.get("SB_MAX_UPLOAD_SIZE", str(100 * 1024 * 1024))),
            delete_jobs_after_analysis=os.environ.get("SB_DELETE_JOBS_AFTER_ANALYSIS", "true").lower() in ("1", "true", "yes", "on"),
            command_timeout=int(os.environ.get("SB_COMMAND_TIMEOUT", "90")),
            extra_scanner_cmd=os.environ.get("SB_EXTRA_SCANNER_CMD"),
            extra_scanner_name=os.environ.get("SB_EXTRA_SCANNER_NAME"),
            rkhunter_cmd=os.environ.get("SB_RKHUNTER_CMD"),
            allow_destructive_actions=os.environ.get("SB_ALLOW_DESTRUCTIVE_ACTIONS", "false").lower() in ("1", "true", "yes", "on"),
            format_cmd=os.environ.get("SB_FORMAT_CMD"),
        )
