"""
ER-Shield v3.0 — Phase 3: Audit Trail & Cloud Architecture
Backend: FastAPI + Supabase (PostgreSQL via asyncpg/SQLAlchemy)
"""

import os
import io
import re
import csv
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from contextlib import asynccontextmanager

import jwt
import pandas as pd
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy import (
    Column, String, Boolean, DateTime, Text, Integer,
    create_engine, func
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# ─────────────────────────────────────────────
# 0. ENVIRONMENT
# ─────────────────────────────────────────────
load_dotenv()

SECRET_KEY  = os.environ["SECRET_KEY"]
GUARD_PIN   = os.environ["GUARD_PIN"]
ADMIN_PIN   = os.environ["ADMIN_PIN"]
DATABASE_URL = os.environ["DATABASE_URL"]
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")

ALGORITHM   = "HS256"
TOKEN_TTL_H = 12
QR_VALIDITY_HOURS = 24  # 24-hour auto-purge window

# ─────────────────────────────────────────────
# 1. DATABASE — SQLAlchemy + Supabase Postgres
# ─────────────────────────────────────────────
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanLog(Base):
    """
    Full audit trail for every entry / exit event.
    One row is created on ENTRY; the same row is updated on EXIT.
    Supports any QR format (no regex validation required).
    """
    __tablename__ = "scan_logs"

    id                 = Column(String, primary_key=True)
    qr_id              = Column(Text, nullable=False, index=True)  # TEXT for unlimited length
    entry_date         = Column(String, nullable=False)
    scan_in_time       = Column(DateTime(timezone=True), nullable=True)
    scan_out_time      = Column(DateTime(timezone=True), nullable=True)
    duration_inside    = Column(String, nullable=True)
    scanned_by_guard   = Column(String, nullable=False)
    gate_id            = Column(String, nullable=True, default="GATE-1")
    guard_notes        = Column(Text, nullable=True)
    is_trauma_override = Column(Boolean, default=False, nullable=False)
    attendants_inside  = Column(String, default="0")
    first_seen_at      = Column(DateTime(timezone=True), nullable=True)  # Track first appearance


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)


# ─────────────────────────────────────────────
# 2. APP & MIDDLEWARE
# ─────────────────────────────────────────────
app = FastAPI(title="ER-Shield API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@app.on_event("startup")
def on_startup():
    init_db()


# ─────────────────────────────────────────────
# 3. PYDANTIC SCHEMAS
# ─────────────────────────────────────────────
class LoginRequest(BaseModel):
    pin: str

class ScanRequest(BaseModel):
    patient_id: str
    is_trauma: bool = False
    gate_id: str = "GATE-1"
    guard_notes: str | None = None


# ─────────────────────────────────────────────
# 4. AUTH HELPERS
# ─────────────────────────────────────────────
def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=TOKEN_TTL_H)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired — please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_guard(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "guard":
        raise HTTPException(status_code=403, detail="Guard access only")
    return user


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access only")
    return user


# ─────────────────────────────────────────────
# 4.5. QR VALIDATION HELPERS
# ─────────────────────────────────────────────
def is_code_expired(first_seen_at: datetime) -> bool:
    """Check if QR code's first entry was more than 24 hours ago"""
    if not first_seen_at:
        return False
    now = datetime.now(timezone.utc)
    age_hours = (now - first_seen_at).total_seconds() / 3600
    return age_hours > QR_VALIDITY_HOURS


# ─────────────────────────────────────────────
# 5. ROUTES
# ─────────────────────────────────────────────

@app.get("/")
async def read_index():
    return FileResponse("index.html")


# ── LOGIN ──────────────────────────────────────
@app.post("/login")
async def login(data: LoginRequest):
    if data.pin == GUARD_PIN:
        token = create_access_token({"sub": "guard", "role": "guard", "pin": GUARD_PIN})
        return {"access_token": token, "token_type": "bearer"}
    if data.pin == ADMIN_PIN:
        token = create_access_token({"sub": "admin", "role": "admin", "pin": ADMIN_PIN})
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid PIN")


# ── ENTRY SCAN (UPDATED: First-Scan Activation + 24hr Expiry + Flexible Payload) ──
@app.post("/scan-pro")
async def verify_entry(
    data: ScanRequest,
    user: dict = Depends(require_guard),
    db: Session = Depends(get_db),
):
    # Take raw QR text exactly as received (NO modification, NO regex validation)
    raw_qr_text = data.patient_id.strip()
    if not raw_qr_text:
        return {"screen_color": "RED", "message": "EMPTY QR CODE", "icon": "🚫"}
    
    today     = datetime.now(timezone.utc)
    today_str = today.strftime("%Y%m%d")
    date_only = today.strftime("%Y-%m-%d")

    # ========== STEP 1: Check if this QR code has ever been seen ==========
    existing_logs = (
        db.query(ScanLog)
        .filter(ScanLog.qr_id == raw_qr_text)
        .order_by(ScanLog.scan_in_time.desc())
        .all()
    )

    # ========== STEP 2: 24-HOUR EXPIRY CHECK (if code exists) ==========
    if existing_logs:
        first_entry = existing_logs[-1]  # oldest record has first_seen_at
        if first_entry.first_seen_at and is_code_expired(first_entry.first_seen_at):
            return {
                "screen_color": "RED", 
                "message": "EXPIRED: QR code超过了24小时有效期", 
                "icon": "⏰",
                "duration": "Contact reception for new slip"
            }

    # ========== STEP 3: Count active sessions for this QR ==========
    active_logs = (
        db.query(ScanLog)
        .filter(
            ScanLog.qr_id == raw_qr_text,
            ScanLog.scan_out_time == None,   # noqa: E711
        )
        .all()
    )

    dynamic_limit = 2 if data.is_trauma else 1

    # ========== STEP 4: FIRST-SCAN ACTIVATION (Onboarding Gate) ==========
    # If no existing logs AND no active sessions → FIRST TIME EVER
    if not existing_logs and len(active_logs) == 0:
        # CREATE NEW ENTRY (First activation)
        new_log = ScanLog(
            id                 = str(uuid.uuid4()),
            qr_id              = raw_qr_text,  # Store raw text as-is
            entry_date         = date_only,
            scan_in_time       = today,
            scanned_by_guard   = user.get("pin", "UNKNOWN"),
            gate_id            = data.gate_id,
            guard_notes        = data.guard_notes,
            is_trauma_override = data.is_trauma,
            first_seen_at      = today,  # Track first appearance for expiry
        )
        db.add(new_log)
        db.commit()
        
        return {
            "screen_color": "GREEN", 
            "message": "FIRST TIME ACCESS GRANTED", 
            "icon": "🆕",
            "log_id": new_log.id
        }

    # ========== STEP 5: NORMAL IN/OUT LIMIT LOGIC ==========
    if len(active_logs) >= dynamic_limit:
        return {
            "screen_color": "RED", 
            "message": "LIMIT FULL - Only {} attendant(s) allowed".format(dynamic_limit), 
            "icon": "🛑"
        }

    # Create new entry session
    new_log = ScanLog(
        id                 = str(uuid.uuid4()),
        qr_id              = raw_qr_text,
        entry_date         = date_only,
        scan_in_time       = today,
        scanned_by_guard   = user.get("pin", "UNKNOWN"),
        gate_id            = data.gate_id,
        guard_notes        = data.guard_notes,
        is_trauma_override = data.is_trauma,
        first_seen_at      = existing_logs[0].first_seen_at if existing_logs else today,
    )
    db.add(new_log)
    db.commit()

    return {
        "screen_color": "GREEN", 
        "message": "ENTRY ALLOWED", 
        "icon": "✔️", 
        "log_id": new_log.id
    }


# ── EXIT SCAN (UPDATED with expiry awareness) ──
@app.get("/exit/{patient_id}")
async def verify_exit(
    patient_id: str,
    gate_id: str = Query(default="GATE-1"),
    guard_notes: str | None = Query(default=None),
    user: dict = Depends(require_guard),
    db: Session = Depends(get_db),
):
    raw_qr_text = patient_id.strip()
    if not raw_qr_text:
        return {"screen_color": "RED", "message": "EMPTY QR CODE", "icon": "🚫"}
    
    today = datetime.now(timezone.utc)

    # ========== Find active session for this QR ==========
    log = (
        db.query(ScanLog)
        .filter(
            ScanLog.qr_id == raw_qr_text,
            ScanLog.scan_out_time == None,   # noqa: E711
        )
        .order_by(ScanLog.scan_in_time.desc())
        .first()
    )

    if not log:
        return {"screen_color": "RED", "message": "NO ACTIVE ENTRY FOUND", "icon": "❌"}

    # ========== Expiry check on exit ==========
    if log.first_seen_at and is_code_expired(log.first_seen_at):
        return {
            "screen_color": "RED", 
            "message": "EXPIRED: QR超过24小时，请联系接待处", 
            "icon": "⏰"
        }

    # Auto-calculate duration
    duration_delta = today - log.scan_in_time.replace(tzinfo=timezone.utc)
    total_seconds  = int(duration_delta.total_seconds())
    hours, rem     = divmod(total_seconds, 3600)
    minutes, secs  = divmod(rem, 60)
    duration_str   = f"{hours:02d}:{minutes:02d}:{secs:02d}"

    log.scan_out_time   = today
    log.duration_inside = duration_str
    log.gate_id         = gate_id
    if guard_notes:
        log.guard_notes = guard_notes
    db.commit()

    return {
        "screen_color": "BLUE",
        "message": f"EXIT RECORDED — Inside for {duration_str}",
        "icon": "📤",
        "duration": duration_str,
    }


# ── ADMIN STATS ────────────────────────────────
@app.get("/api/stats")
async def get_stats(
    user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    total_inside  = db.query(ScanLog).filter(
        ScanLog.entry_date == today,
        ScanLog.scan_out_time == None,   # noqa: E711
    ).count()

    daily_traffic = db.query(ScanLog).filter(
        ScanLog.entry_date == today
    ).count()

    capacity_pct  = round((total_inside / 50) * 100, 1)

    return {
        "total_inside":        total_inside,
        "daily_traffic":       daily_traffic,
        "capacity_percentage": capacity_pct,
    }


# ── SHARED: build report rows ───────────────────
def _build_rows(logs, target_date: str) -> list:
    rows = []
    for log in logs:
        rows.append({
            "QR ID (Raw)":       log.qr_id[:500] + "..." if len(log.qr_id) > 500 else log.qr_id,
            "Entry Date":        log.entry_date,
            "Scan In Time":      log.scan_in_time.strftime("%Y-%m-%d %H:%M:%S") if log.scan_in_time else "",
            "Scan Out Time":     log.scan_out_time.strftime("%Y-%m-%d %H:%M:%S") if log.scan_out_time else "STILL INSIDE",
            "Duration Inside":   log.duration_inside or "N/A",
            "Scanned By Guard":  log.scanned_by_guard,
            "Gate ID":           log.gate_id or "",
            "Guard Notes":       log.guard_notes or "",
            "Trauma Override":   "YES" if log.is_trauma_override else "NO",
            "First Seen At":     log.first_seen_at.strftime("%Y-%m-%d %H:%M:%S") if log.first_seen_at else "",
        })
    if not rows:
        rows = [{"Message": f"No scan records found for {target_date}"}]
    return rows


# ── CSV EXPORT ─────────────────────────────────
@app.get("/api/export")
async def export_csv(
    date: str | None = Query(default=None, description="YYYY-MM-DD (defaults to today)"),
    user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target_date = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    logs        = db.query(ScanLog).filter(ScanLog.entry_date == target_date).all()
    rows        = _build_rows(logs, target_date)

    df     = pd.DataFrame(rows)
    stream = io.StringIO()
    df.to_csv(stream, index=False)
    stream.seek(0)

    filename = f"ER_Shield_Report_{target_date}.csv"
    return StreamingResponse(
        iter([stream.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── EXCEL EXPORT (forensic report for MS) ──────
@app.get("/api/export/excel")
async def export_excel(
    date: str | None = Query(default=None, description="YYYY-MM-DD (defaults to today)"),
    user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target_date = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    logs        = db.query(ScanLog).filter(ScanLog.entry_date == target_date).all()
    rows        = _build_rows(logs, target_date)

    df     = pd.DataFrame(rows)
    stream = io.BytesIO()

    with pd.ExcelWriter(stream, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Shift Report")
        ws = writer.sheets["Shift Report"]
        # Auto-width columns for clean professional look
        for col in ws.columns:
            max_len = max(len(str(cell.value or "")) for cell in col) + 4
            ws.column_dimensions[col[0].column_letter].width = min(max_len, 40)

    stream.seek(0)
    filename = f"ER_Shield_Forensic_{target_date}.xlsx"
    return StreamingResponse(
        iter([stream.read()]),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── CLEANUP ENDPOINT (Manual expiry purge - Admin only) ──
@app.post("/api/purge-expired")
async def purge_expired_codes(
    user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Admin endpoint to manually lock/flag all QR codes older than 24 hours"""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=QR_VALIDITY_HOURS)
    
    # Find all active entries older than 24 hours
    expired_active = db.query(ScanLog).filter(
        ScanLog.first_seen_at < cutoff,
        ScanLog.scan_out_time == None
    ).all()
    
    expired_count = len(expired_active)
    
    # Force exit for all expired entries
    for log in expired_active:
        now = datetime.now(timezone.utc)
        duration_delta = now - log.scan_in_time.replace(tzinfo=timezone.utc)
        total_seconds = int(duration_delta.total_seconds())
        hours, rem = divmod(total_seconds, 3600)
        minutes, secs = divmod(rem, 60)
        duration_str = f"{hours:02d}:{minutes:02d}:{secs:02d}"
        
        log.scan_out_time = now
        log.duration_inside = duration_str
        log.guard_notes = (log.guard_notes or "") + " [AUTO-PURGED: QR超过24小时]"
    
    db.commit()
    
    return {
        "status": "success",
        "purged_count": expired_count,
        "message": f"Auto-exited {expired_count} expired QR sessions (超过24小时)"
    }


# ── HEALTH CHECK ───────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "version": "3.0.0", "timestamp": datetime.now(timezone.utc).isoformat()}