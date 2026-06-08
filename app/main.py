from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pathlib import Path, PureWindowsPath, PurePosixPath
import os
import shutil
import uuid
import json
import sys
import re
import shlex


APP_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = APP_DIR.parent

# Permet d'importer analyzer/ quand on lance :
# uvicorn app.main:app --host 127.0.0.1 --port 8080 --reload
sys.path.insert(0, str(PROJECT_ROOT))

from analyzer.engine import AnalysisEngine
from analyzer.config import Settings
from analyzer.logger import EventLogger
from analyzer.utils import run_cmd


settings = Settings.from_env()

# Utile en mode dev Windows/Linux : crée les dossiers si absents.
settings.jobs_dir.mkdir(parents=True, exist_ok=True)
settings.reports_dir.mkdir(parents=True, exist_ok=True)
settings.quarantine_dir.mkdir(parents=True, exist_ok=True)
settings.rules_dir.mkdir(parents=True, exist_ok=True)
settings.tmp_dir.mkdir(parents=True, exist_ok=True)
settings.events_log.parent.mkdir(parents=True, exist_ok=True)

engine = AnalysisEngine(settings)
event_logger = EventLogger(settings.events_log)

app = FastAPI(
    title="Station Blanche VT",
    version="1.0.0",
)

app.mount(
    "/static",
    StaticFiles(directory=str(APP_DIR / "static")),
    name="static",
)

templates = Jinja2Templates(
    directory=str(APP_DIR / "templates")
)


def sanitize_filename(filename: str) -> str:
    """
    Nettoyage compatible Windows/Linux pour éviter :
    - chemins complets transmis par certains navigateurs ;
    - caractères interdits Windows ;
    - caractères de contrôle ;
    - noms réservés Windows ;
    - noms vides ou problématiques.
    """
    if not filename:
        return "upload.bin"

    # Gère les chemins Windows du type C:\\fakepath\\file.txt
    name = PureWindowsPath(filename).name

    # Gère aussi les chemins POSIX éventuels
    name = PurePosixPath(name).name

    # Supprime caractères interdits Windows/Linux et caractères de contrôle
    name = re.sub(r'[\x00-\x1f<>:"/\\|?*]+', "_", name)

    # Supprime espaces et points finaux problématiques sous Windows
    name = name.strip().strip(".")

    # Évite les noms réservés Windows
    reserved = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    }

    stem = name.split(".")[0].upper()
    if not name or stem in reserved:
        name = "upload.bin"

    # Limite raisonnable pour éviter les chemins trop longs
    return name[:150]


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "vt_enabled": bool(settings.vt_api_key),
            "upload_enabled": settings.vt_enable_upload,
            "extra_scanner_enabled": bool(settings.extra_scanner_cmd),
            "extra_scanner_name": settings.extra_scanner_name,
            "allow_destructive": settings.allow_destructive_actions,
        },
    )


@app.post("/analyze_path", response_class=HTMLResponse)
def analyze_path(request: Request, target_path: str = Form(...), allow_vt_upload: str | None = Form(default=None)):
    p = Path(target_path)
    if not p.exists():
        raise HTTPException(status_code=404, detail="Chemin introuvable")

    job_id = str(uuid.uuid4())
    job_dir = settings.jobs_dir / job_id
    job_dir.mkdir(parents=True, mode=0o750, exist_ok=False)

    event_logger.log({"event": "path_analysis_requested", "job_id": job_id, "path": str(p)})

    report = engine.analyze(p, job_id=job_id, allow_vt_upload=bool(allow_vt_upload))

    report_path = settings.reports_dir / f"{job_id}.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    event_logger.log({"event": "analysis_completed", "job_id": job_id, "path": str(p), "file_count": report.get("file_count")})

    if report.get("schema") == "station-blanche-bulk-report-v1":
        return templates.TemplateResponse(request, "result_bulk.html", {
            "report": report,
            "job_id": job_id,
            "report_file": f"/reports/{job_id}.json",
            "allow_destructive": settings.allow_destructive_actions,
        })

    return templates.TemplateResponse(request, "result.html", {
        "report": report,
        "job_id": job_id,
        "report_file": f"/reports/{job_id}.json",
        "allow_destructive": settings.allow_destructive_actions,
    })


@app.post("/delete_path", response_class=HTMLResponse)
def delete_path(request: Request, target_path: str = Form(...)):
    if not settings.allow_destructive_actions:
        raise HTTPException(status_code=403, detail="Actions destructrices désactivées")

    p = Path(target_path)
    if not p.exists():
        raise HTTPException(status_code=404, detail="Chemin introuvable")

    job_id = str(uuid.uuid4())
    event_logger.log({"event": "delete_requested", "job_id": job_id, "path": str(p)})

    try:
        if p.is_file():
            p.unlink()
        elif p.is_dir():
            shutil.rmtree(p)
        else:
            raise HTTPException(status_code=400, detail="Type de chemin non pris en charge")
    except Exception as exc:
        event_logger.log({"event": "delete_error", "job_id": job_id, "error": str(exc)})
        raise HTTPException(status_code=500, detail=f"Erreur suppression: {exc}")

    event_logger.log({"event": "delete_completed", "job_id": job_id, "path": str(p)})
    return templates.TemplateResponse(request, "index.html", {"vt_enabled": bool(settings.vt_api_key), "upload_enabled": settings.vt_enable_upload, "extra_scanner_enabled": bool(settings.extra_scanner_cmd), "extra_scanner_name": settings.extra_scanner_name, "allow_destructive": settings.allow_destructive_actions, "message": f"Suppression réussie : {p}"})


@app.post("/format_path", response_class=HTMLResponse)
def format_path(request: Request, target_path: str = Form(...)):
    if not settings.allow_destructive_actions or not settings.format_cmd:
        raise HTTPException(status_code=403, detail="Formatage non autorisé ou commande absente")

    p = Path(target_path)
    if not p.exists():
        raise HTTPException(status_code=404, detail="Chemin introuvable")

    job_id = str(uuid.uuid4())
    event_logger.log({"event": "format_requested", "job_id": job_id, "path": str(p)})

    try:
        cmd = settings.format_cmd.format(path=str(p))
        result = run_cmd(shlex.split(cmd), timeout=settings.command_timeout)
    except Exception as exc:
        event_logger.log({"event": "format_error", "job_id": job_id, "error": str(exc)})
        raise HTTPException(status_code=500, detail=f"Erreur formatage: {exc}")

    event_logger.log({"event": "format_completed", "job_id": job_id, "path": str(p), "result": result})
    return templates.TemplateResponse(request, "index.html", {"vt_enabled": bool(settings.vt_api_key), "upload_enabled": settings.vt_enable_upload, "extra_scanner_enabled": bool(settings.extra_scanner_cmd), "extra_scanner_name": settings.extra_scanner_name, "allow_destructive": settings.allow_destructive_actions, "message": f"Formatage lancé : {p}", "format_result": result})


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(
    request: Request,
    files: list[UploadFile] = File(...),
    allow_vt_upload: str | None = Form(default=None),
):
    # Accept single file or multiple files (e.g. directory upload via webkitdirectory).
    if not files:
        raise HTTPException(status_code=400, detail="Aucun fichier fourni")

    job_id = str(uuid.uuid4())
    job_dir = settings.jobs_dir / job_id
    job_dir.mkdir(parents=True, mode=0o750, exist_ok=False)

    total_size = 0

    def sanitize_path_components(p: str) -> Path:
        # Preserve relative directories from client (they may include / or \\)
        parts = re.split(r"[\\/]+", p)
        safe_parts = [sanitize_filename(part) for part in parts if part and part != '.' and part != '..']
        return Path("/").joinpath(*safe_parts).relative_to('/')

    try:
        for upload in files:
            if not upload.filename:
                continue

            rel = sanitize_path_components(upload.filename)
            target = job_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)

            # Save file
            with target.open('wb') as out:
                while True:
                    chunk = await upload.read(1024 * 1024)
                    if not chunk:
                        break
                    total_size += len(chunk)
                    if total_size > settings.max_upload_size:
                        shutil.rmtree(job_dir, ignore_errors=True)
                        raise HTTPException(status_code=413, detail="Fichiers trop volumineux")
                    out.write(chunk)

            try:
                os.chmod(target, 0o400)
            except OSError:
                pass

            event_logger.log({
                "event": "upload_received",
                "job_id": job_id,
                "filename": str(rel),
                "original_filename": upload.filename,
                "size_sum": total_size,
                "client": request.client.host if request.client else None,
            })

        # If only one file and no directory structure, analyze that file; else analyze the job_dir directory
        saved_files = list(job_dir.rglob('*'))
        single_file = None
        files_only = [p for p in saved_files if p.is_file()]
        if len(files_only) == 1:
            single_file = files_only[0]

        target_to_analyze = single_file if single_file is not None else job_dir

        report = engine.analyze(target_to_analyze, job_id=job_id, allow_vt_upload=bool(allow_vt_upload))

        report_path = settings.reports_dir / f"{job_id}.json"
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

        try:
            os.chmod(report_path, 0o640)
        except OSError:
            pass

        event_logger.log({
            "event": "analysis_completed",
            "job_id": job_id,
            "target": str(target_to_analyze),
            "verdict": report.get("verdict"),
        })

        if settings.delete_jobs_after_analysis and report.get("verdict") != "malveillant":
            shutil.rmtree(job_dir, ignore_errors=True)

        template = "result.html" if report.get('schema') == 'station-blanche-report-v1' else 'result_bulk.html'

        return templates.TemplateResponse(
            request,
            template,
            {
                "report": report,
                "job_id": job_id,
                "report_file": f"/reports/{job_id}.json",
                "allow_destructive": settings.allow_destructive_actions,
            },
        )

    except HTTPException:
        raise
    except Exception as exc:
        event_logger.log({"event": "analysis_error", "job_id": job_id, "error": str(exc)})
        raise HTTPException(status_code=500, detail=f"Erreur pendant l'analyse : {exc}") from exc


@app.get("/reports/{job_id}.json")
def get_report(job_id: str):
    # UUID classique : lettres, chiffres et tirets uniquement.
    if not job_id.replace("-", "").isalnum():
        raise HTTPException(
            status_code=400,
            detail="Identifiant invalide",
        )

    path = settings.reports_dir / f"{job_id}.json"

    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail="Rapport introuvable",
        )

    return FileResponse(
        str(path),
        media_type="application/json",
        filename=f"station-blanche-{job_id}.json",
    )


@app.get("/healthz")
def healthz():
    return {
        "status": "ok",
        "vt_enabled": bool(settings.vt_api_key),
        "vt_upload_enabled": settings.vt_enable_upload,
        "base_dir": str(settings.base_dir),
        "jobs_dir": str(settings.jobs_dir),
        "reports_dir": str(settings.reports_dir),
    }