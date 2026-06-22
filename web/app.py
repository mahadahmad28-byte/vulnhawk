"""VulnHawk Web Dashboard — FastAPI app with Jinja2 templates.

Allows scanning via browser, viewing past results, and downloading reports.
"""

# Adjust sys.path so vulnhawk package is importable
import sys
from datetime import datetime
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

import vulnhawk.scanners  # noqa: F401 — registers all scanner plugins
from vulnhawk.core.crawler import crawl_target
from vulnhawk.core.reporter import generate_html_report, generate_json_report
from vulnhawk.core.scanner import run_all_scanners

app = FastAPI(
    title="VulnHawk Dashboard",
    description="Web Vulnerability Scanner — Browser Interface",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Reports directory
REPORTS_DIR = Path("./reports")
REPORTS_DIR.mkdir(exist_ok=True)

# In-memory scan status store
_scans: dict[str, dict] = {}

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


class ScanRequest(BaseModel):
    target: str
    depth: int = 2
    threads: int = 10
    # Authenticated scanning (optional)
    login_url: str | None = None
    username: str | None = None
    password: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard HTML
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Serve the main dashboard page."""
    return templates.TemplateResponse(request=request, name="dashboard.html")


# ─────────────────────────────────────────────────────────────────────────────
# Scan API
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """Start an async vulnerability scan. Returns a scan_id to poll status."""
    import uuid
    scan_id = uuid.uuid4().hex[:8]
    _scans[scan_id] = {
        "scan_id": scan_id,
        "target": req.target,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "progress": "Initializing…",
        "findings": [],
        "report_html": None,
        "report_json": None,
    }
    background_tasks.add_task(_run_scan, scan_id, req)
    return {"scan_id": scan_id, "status": "running"}


async def _run_scan(scan_id: str, req: ScanRequest):
    """Background task that runs the full scan pipeline."""
    scan = _scans[scan_id]
    try:
        # 1. Crawl
        scan["progress"] = "Crawling target…"
        crawl_result = await crawl_target(
            req.target,
            max_depth=req.depth,
            max_concurrent=req.threads,
            login_url=req.login_url,
            username=req.username,
            password=req.password,
        )

        # 2. Run all registered scanners using the framework
        scan["progress"] = "Running scanners…"
        all_vulns = await run_all_scanners(crawl_result)

        # 3. Generate reports
        scan["progress"] = "Generating report…"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_slug = req.target.replace("://", "_").replace("/", "_").replace(".", "_")[:30]

        html_path = str(REPORTS_DIR / f"{target_slug}_{timestamp}.html")
        json_path = str(REPORTS_DIR / f"{target_slug}_{timestamp}.json")

        generate_html_report(all_vulns, req.target, html_path)
        generate_json_report(all_vulns, req.target, json_path)

        # 4. Update scan record
        scan["status"] = "complete"
        scan["progress"] = "Done"
        scan["findings"] = [
            {
                "title": v.title,
                "severity": v.severity,
                "url": v.url,
                "description": v.description,
                "remediation": v.remediation,
                "scanner": v.scanner_name,
            }
            for v in all_vulns
        ]
        scan["report_html"] = html_path
        scan["report_json"] = json_path
        scan["finished_at"] = datetime.now().isoformat()

    except Exception as e:
        scan["status"] = "error"
        scan["progress"] = f"Error: {e}"


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Poll scan status and results."""
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/api/scans")
async def list_scans():
    """List all scans (most recent first)."""
    scans = sorted(_scans.values(), key=lambda s: s["started_at"], reverse=True)
    return {"scans": scans}


@app.get("/api/report/{scan_id}/html")
async def download_html_report(scan_id: str):
    """Download the HTML report for a completed scan."""
    scan = _scans.get(scan_id)
    if not scan or not scan.get("report_html"):
        raise HTTPException(status_code=404, detail="Report not ready")
    return FileResponse(
        scan["report_html"],
        media_type="text/html",
        filename=Path(scan["report_html"]).name,
    )


@app.get("/api/report/{scan_id}/json")
async def download_json_report(scan_id: str):
    """Download the JSON report for a completed scan."""
    scan = _scans.get(scan_id)
    if not scan or not scan.get("report_json"):
        raise HTTPException(status_code=404, detail="Report not ready")
    return FileResponse(
        scan["report_json"],
        media_type="application/json",
        filename=Path(scan["report_json"]).name,
    )


@app.get("/api/report/{scan_id}/pdf")
async def download_pdf_report(scan_id: str):
    """Download the PDF report for a completed scan (requires vulnhawk[pdf])."""
    from vulnhawk.core.reporter import generate_pdf_report

    scan = _scans.get(scan_id)
    if not scan or scan.get("status") != "complete":
        raise HTTPException(status_code=404, detail="Scan not complete")

    html_path = scan.get("report_html")
    if not html_path:
        raise HTTPException(status_code=404, detail="HTML report not found")

    pdf_path = html_path.replace(".html", ".pdf")
    if not Path(pdf_path).exists():
        # Generate from stored vulnerabilities
        from vulnhawk.core.scanner import Vulnerability  # noqa: F401
        findings = scan.get("findings", [])
        vulns = [
            type("V", (), {
                "title": f["title"],
                "severity": f["severity"],
                "url": f["url"],
                "description": f["description"],
                "remediation": f.get("remediation", ""),
                "evidence": f.get("evidence"),
                "scanner_name": f.get("scanner", ""),
                "cvss_score": f.get("cvss_score"),
                "references": f.get("references", []),
            })()
            for f in findings
        ]
        try:
            pdf_path = generate_pdf_report(vulns, scan["target"], pdf_path)
        except ImportError:
            raise HTTPException(
                status_code=501,
                detail="PDF export requires WeasyPrint. Install with: pip install vulnhawk[pdf]",
            )

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=Path(pdf_path).name,
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("web.app:app", host="0.0.0.0", port=8080, reload=True)
