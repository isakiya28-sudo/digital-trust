import os
from contextlib import asynccontextmanager
from typing import Optional, List
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from models import (
    MessageScanRequest,
    UrlScanRequest,
    TextContentScanRequest,
    ScanResult,
    ScanHistoryItem,
    DashboardStats
)
from database import (
    init_db,
    insert_scan,
    get_recent_scans,
    get_dashboard_stats,
    clear_all_scans
)
from scanners.message_scanner import scan_message
from scanners.url_scanner import scan_url
from scanners.content_scanner import scan_text_content, scan_image_content

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database on startup
    init_db()
    yield

app = FastAPI(
    title="Digital Trust — AI Security & Verification API",
    description="Intelligent scam detection, URL threat inspection, and content verification backend.",
    version="2.1.0",
    lifespan=lifespan
)

# Enable CORS for local frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {
        "service": "Digital Trust API",
        "tagline": "Think Before You Trust.",
        "status": "online",
        "version": "2.1.0",
        "documentation": "/docs"
    }

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "engine": "Heuristic Security Evaluator",
        "database": "SQLite Operational",
        "ai_model_connected": False,
        "ai_model_notice": "Running certified deterministic heuristic fallback."
    }

@app.post("/api/analyze-message", response_model=ScanResult)
def analyze_message_endpoint(req: MessageScanRequest):
    if not req.text or not req.text.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Message text cannot be empty."
        )
    result = scan_message(req.text)
    insert_scan(result)
    return result

@app.post("/api/analyze-url", response_model=ScanResult)
def analyze_url_endpoint(req: UrlScanRequest):
    if not req.url or not req.url.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="URL string cannot be empty."
        )
    result = scan_url(req.url)
    insert_scan(result)
    return result

@app.post("/api/analyze-content", response_model=ScanResult)
async def analyze_content_endpoint(
    text: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None)
):
    if file:
        file_bytes = await file.read()
        if not file_bytes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty."
            )
        result = scan_image_content(file_bytes, file.filename or "uploaded_media")
        insert_scan(result)
        return result
    elif text and text.strip():
        result = scan_text_content(text)
        insert_scan(result)
        return result
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Please provide either 'text' content or an 'image' file to analyze."
        )

# Fallback JSON endpoint specifically for text content
@app.post("/api/analyze-content/text", response_model=ScanResult)
def analyze_content_text_endpoint(req: TextContentScanRequest):
    result = scan_text_content(req.text)
    insert_scan(result)
    return result

@app.get("/api/scan-history", response_model=List[ScanHistoryItem])
def scan_history_endpoint(limit: int = 15):
    return get_recent_scans(limit=min(limit, 50))

@app.get("/api/dashboard-stats", response_model=DashboardStats)
def dashboard_stats_endpoint():
    return get_dashboard_stats()

@app.delete("/api/clear-history")
def clear_history_endpoint():
    clear_all_scans()
    return {"message": "All scan records cleared successfully."}

# Mount static build if frontend/dist exists for unified full-stack hosting
DIST_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
if os.path.exists(DIST_DIR):
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse

    assets_dir = os.path.join(DIST_DIR, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}")
    def serve_frontend_spa(full_path: str):
        # Do not catch /api paths
        if full_path.startswith("api/") or full_path == "api":
            raise HTTPException(status_code=404, detail="API route not found")
        file_path = os.path.join(DIST_DIR, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(DIST_DIR, "index.html"))

