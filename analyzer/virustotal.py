from pathlib import Path
import requests
import time
import os

VT_BASE = "https://www.virustotal.com/api/v3"

class VirusTotalClient:
    def __init__(self, api_key: str | None):
        self.api_key = api_key

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _headers(self):
        return {"x-apikey": self.api_key or ""}

    def get_file_report(self, sha256: str) -> dict:
        if not self.enabled:
            return {"enabled": False, "known": None, "uploaded": False, "stats": None, "error": "VT_API_KEY non définie"}
        try:
            r = requests.get(f"{VT_BASE}/files/{sha256}", headers=self._headers(), timeout=30)
            if r.status_code == 404:
                return {"enabled": True, "known": False, "uploaded": False, "stats": None, "raw": None, "error": None}
            r.raise_for_status()
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"enabled": True, "known": True, "uploaded": False, "stats": stats, "raw": data, "error": None}
        except Exception as e:
            return {"enabled": True, "known": None, "uploaded": False, "stats": None, "raw": None, "error": str(e)}

    def upload_file(self, path: Path) -> dict:
        if not self.enabled:
            return {"enabled": False, "known": None, "uploaded": False, "stats": None, "error": "VT_API_KEY non définie"}
        try:
            with path.open("rb") as f:
                files = {"file": (path.name, f)}
                r = requests.post(f"{VT_BASE}/files", headers=self._headers(), files=files, timeout=180)
            r.raise_for_status()
            data = r.json()
            analysis_id = data.get("data", {}).get("id")
            return {"enabled": True, "uploaded": True, "analysis_id": analysis_id, "raw_upload": data, "error": None}
        except Exception as e:
            return {"enabled": True, "uploaded": False, "analysis_id": None, "raw_upload": None, "error": str(e)}

    def get_analysis(self, analysis_id: str) -> dict:
        if not self.enabled:
            return {"error": "VT_API_KEY non définie"}
        try:
            r = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=self._headers(), timeout=30)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"error": str(e)}
