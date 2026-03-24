"""
server.py — FastAPI 백엔드
병리팀 PC 보안점수 IP 지도 시스템

실행: pip install fastapi uvicorn pandas openpyxl python-multipart
      uvicorn server:app --host 0.0.0.0 --port 8000 --reload
"""
import sqlite3
import os
import math
import io
import hashlib
import secrets
from contextlib import contextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import pandas as pd

# ── DB ──

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "security_map.db")

def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

@contextmanager
def db():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    with db() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS labs (
                lab_id TEXT PRIMARY KEY, lab_name TEXT NOT NULL,
                grid_rows INTEGER DEFAULT 8, grid_cols INTEGER DEFAULT 8,
                display_order INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS pcs (
                pc_id TEXT PRIMARY KEY, ip_address TEXT UNIQUE NOT NULL,
                pc_name TEXT, lab_id TEXT NOT NULL REFERENCES labs(lab_id),
                grid_row INTEGER NOT NULL, grid_col INTEGER NOT NULL,
                location TEXT, detail TEXT, memo TEXT DEFAULT '',
                UNIQUE(lab_id, grid_row, grid_col));
            CREATE TABLE IF NOT EXISTS security_scores (
                ip_address TEXT PRIMARY KEY, security_score INTEGER,
                upload_date TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS upload_history (
                upload_id INTEGER PRIMARY KEY AUTOINCREMENT,
                upload_date TEXT NOT NULL, file_name TEXT,
                total_count INTEGER, matched INTEGER, unmatched INTEGER);
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                lab_id TEXT,
                created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL);
        """)
        # 기본 관리자 계정 생성 (사번: admin, 비번: admin1234)
        existing = c.execute("SELECT 1 FROM users WHERE user_id='admin'").fetchone()
        if not existing:
            c.execute("INSERT INTO users VALUES (?,?,?,?,?,?)",
                      ('admin', '관리자', hash_pw('admin1234'), 'admin', None,
                       datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

init_db()

# 마이그레이션 (기존 DB 호환)
with db() as c:
    for sql in [
        "ALTER TABLE pcs ADD COLUMN memo TEXT DEFAULT ''",
        "CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, username TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', lab_id TEXT, created_at TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT NOT NULL)",
    ]:
        try:
            c.execute(sql)
        except:
            pass
    # 기본 관리자 계정 (없을 경우)
    try:
        existing = c.execute("SELECT 1 FROM users WHERE user_id='admin'").fetchone()
        if not existing:
            c.execute("INSERT INTO users VALUES (?,?,?,?,?,?)",
                      ('admin', '관리자', hash_pw('admin1234'), 'admin', None,
                       datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    except:
        pass

# ── FastAPI ──

app = FastAPI(title="병리팀 보안점수 API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    def serve_index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


# ── 인증 헬퍼 ──

def get_current_user(request: Request):
    token = request.headers.get("X-Token") or request.cookies.get("token")
    if not token:
        raise HTTPException(401, "로그인이 필요합니다")
    with db() as c:
        row = c.execute(
            "SELECT u.* FROM sessions s JOIN users u ON s.user_id=u.user_id WHERE s.token=?",
            (token,)
        ).fetchone()
    if not row:
        raise HTTPException(401, "세션이 만료됐습니다. 다시 로그인하세요")
    return dict(row)

def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "관리자 권한이 필요합니다")
    return user

def check_lab_access(user: dict, lab_id: str):
    """일반 사용자는 자기 검사실만 접근 가능"""
    if user["role"] == "admin":
        return True
    if user["lab_id"] == lab_id:
        return True
    raise HTTPException(403, "해당 검사실에 대한 권한이 없습니다")


# ── Models ──

class LoginRequest(BaseModel):
    user_id: str
    password: str

class UserCreate(BaseModel):
    user_id: str
    username: str
    password: str
    role: str = "user"
    lab_id: Optional[str] = None

class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None
    lab_id: Optional[str] = None

class LabCreate(BaseModel):
    lab_name: str
    grid_rows: int = 8
    grid_cols: int = 8

class LabUpdate(BaseModel):
    lab_name: Optional[str] = None
    grid_rows: Optional[int] = None
    grid_cols: Optional[int] = None

class PcCreate(BaseModel):
    ip_address: str
    pc_name: str = ""
    lab_id: str
    grid_row: int
    grid_col: int
    location: str = ""
    detail: str = ""
    memo: str = ""

class PcUpdate(BaseModel):
    ip_address: Optional[str] = None
    pc_name: Optional[str] = None
    lab_id: Optional[str] = None
    grid_row: Optional[int] = None
    grid_col: Optional[int] = None
    location: Optional[str] = None
    detail: Optional[str] = None
    memo: Optional[str] = None

class PcMove(BaseModel):
    grid_row: int
    grid_col: int


# ── Auth API ──

@app.post("/api/login")
def login(data: LoginRequest):
    with db() as c:
        user = c.execute(
            "SELECT * FROM users WHERE user_id=? AND password_hash=?",
            (data.user_id, hash_pw(data.password))
        ).fetchone()
    if not user:
        raise HTTPException(401, "사번 또는 비밀번호가 올바르지 않습니다")
    token = secrets.token_hex(32)
    with db() as c:
        # 기존 세션 삭제 후 새 세션 발급
        c.execute("DELETE FROM sessions WHERE user_id=?", (user["user_id"],))
        c.execute("INSERT INTO sessions VALUES (?,?,?)",
                  (token, user["user_id"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    return {
        "token": token,
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "lab_id": user["lab_id"]
    }

@app.post("/api/logout")
def logout(user=Depends(get_current_user), request: Request = None):
    token = request.headers.get("X-Token") or request.cookies.get("token")
    with db() as c:
        c.execute("DELETE FROM sessions WHERE token=?", (token,))
    return {"ok": True}

@app.get("/api/me")
def me(user=Depends(get_current_user)):
    return {
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "lab_id": user["lab_id"]
    }

@app.post("/api/change-password")
def change_password(data: dict, user=Depends(get_current_user)):
    old_pw = data.get("old_password", "")
    new_pw = data.get("new_password", "")
    if not new_pw or len(new_pw) < 4:
        raise HTTPException(400, "새 비밀번호는 4자 이상이어야 합니다")
    with db() as c:
        row = c.execute(
            "SELECT 1 FROM users WHERE user_id=? AND password_hash=?",
            (user["user_id"], hash_pw(old_pw))
        ).fetchone()
        if not row:
            raise HTTPException(400, "현재 비밀번호가 올바르지 않습니다")
        c.execute("UPDATE users SET password_hash=? WHERE user_id=?",
                  (hash_pw(new_pw), user["user_id"]))
    return {"ok": True}


# ── Users API (관리자 전용) ──

@app.get("/api/users")
def list_users(user=Depends(require_admin)):
    with db() as c:
        rows = c.execute("SELECT user_id, username, role, lab_id, created_at FROM users").fetchall()
        return [dict(r) for r in rows]

@app.post("/api/users")
def create_user(data: UserCreate, user=Depends(require_admin)):
    with db() as c:
        existing = c.execute("SELECT 1 FROM users WHERE user_id=?", (data.user_id,)).fetchone()
        if existing:
            raise HTTPException(400, "이미 존재하는 사번입니다")
        c.execute("INSERT INTO users VALUES (?,?,?,?,?,?)",
                  (data.user_id, data.username, hash_pw(data.password),
                   data.role, data.lab_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    return {"ok": True}

@app.put("/api/users/{user_id}")
def update_user(user_id: str, data: UserUpdate, user=Depends(require_admin)):
    with db() as c:
        if data.username is not None:
            c.execute("UPDATE users SET username=? WHERE user_id=?", (data.username, user_id))
        if data.password is not None:
            c.execute("UPDATE users SET password_hash=? WHERE user_id=?",
                      (hash_pw(data.password), user_id))
        if data.role is not None:
            c.execute("UPDATE users SET role=? WHERE user_id=?", (data.role, user_id))
        if data.lab_id is not None:
            c.execute("UPDATE users SET lab_id=? WHERE user_id=?", (data.lab_id, user_id))
    return {"ok": True}

@app.delete("/api/users/{user_id}")
def delete_user(user_id: str, user=Depends(require_admin)):
    if user_id == "admin":
        raise HTTPException(400, "기본 관리자 계정은 삭제할 수 없습니다")
    with db() as c:
        c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM users WHERE user_id=?", (user_id,))
    return {"ok": True}


# ── Labs API ──

@app.get("/api/labs")
def list_labs(user=Depends(get_current_user)):
    with db() as c:
        # 모든 사용자 전체 검사실 조회 가능
        return [dict(r) for r in c.execute("SELECT * FROM labs ORDER BY display_order").fetchall()]

@app.post("/api/labs")
def create_lab(data: LabCreate, user=Depends(require_admin)):
    with db() as c:
        mx = c.execute("SELECT COALESCE(MAX(display_order),0) FROM labs").fetchone()[0]
        lab_id = data.lab_name.strip().replace(" ","_").lower()
        c.execute("INSERT INTO labs VALUES (?,?,?,?,?)",
                  (lab_id, data.lab_name, data.grid_rows, data.grid_cols, mx+1))
        return {"lab_id": lab_id}

@app.put("/api/labs/{lab_id}")
def update_lab(lab_id: str, data: LabUpdate, user=Depends(require_admin)):
    with db() as c:
        if data.lab_name is not None:
            c.execute("UPDATE labs SET lab_name=? WHERE lab_id=?", (data.lab_name, lab_id))
        if data.grid_rows is not None:
            c.execute("UPDATE labs SET grid_rows=? WHERE lab_id=?", (data.grid_rows, lab_id))
        if data.grid_cols is not None:
            c.execute("UPDATE labs SET grid_cols=? WHERE lab_id=?", (data.grid_cols, lab_id))
    return {"ok": True}

@app.delete("/api/labs/{lab_id}")
def delete_lab(lab_id: str, user=Depends(require_admin)):
    with db() as c:
        c.execute("DELETE FROM security_scores WHERE ip_address IN (SELECT ip_address FROM pcs WHERE lab_id=?)", (lab_id,))
        c.execute("DELETE FROM pcs WHERE lab_id=?", (lab_id,))
        c.execute("DELETE FROM labs WHERE lab_id=?", (lab_id,))
    return {"ok": True}


# ── PCs API ──

@app.get("/api/pcs")
def list_pcs(lab_id: Optional[str] = None, user=Depends(get_current_user)):
    with db() as c:
        # 모든 사용자 전체 PC 조회 가능 (조회는 제한 없음)
        if lab_id:
            return [dict(r) for r in c.execute(
                "SELECT * FROM pcs WHERE lab_id=? ORDER BY grid_row,grid_col", (lab_id,)
            ).fetchall()]
        return [dict(r) for r in c.execute("SELECT * FROM pcs ORDER BY lab_id,grid_row,grid_col").fetchall()]

@app.post("/api/pcs")
def create_pc(data: PcCreate, user=Depends(get_current_user)):
    check_lab_access(user, data.lab_id)
    pc_id = f"pc_{data.ip_address.replace('.','_')}"
    with db() as c:
        c.execute("INSERT INTO pcs VALUES (?,?,?,?,?,?,?,?,?)",
                  (pc_id, data.ip_address, data.pc_name, data.lab_id,
                   data.grid_row, data.grid_col, data.location, data.detail, data.memo))
    return {"pc_id": pc_id}

@app.put("/api/pcs/{pc_id}")
def update_pc(pc_id: str, data: PcUpdate, user=Depends(get_current_user)):
    with db() as c:
        pc = c.execute("SELECT lab_id FROM pcs WHERE pc_id=?", (pc_id,)).fetchone()
        if not pc:
            raise HTTPException(404, "PC를 찾을 수 없습니다")
        check_lab_access(user, pc["lab_id"])
        update_data = data.dict(exclude_none=True)
        if not update_data:
            return {"ok": True}
        if 'lab_id' in update_data:
            if user["role"] != "admin":
                raise HTTPException(403, "검사실 이관은 관리자만 가능합니다")
            c.execute("UPDATE pcs SET grid_row=-1, grid_col=-1 WHERE pc_id=?", (pc_id,))
        fields = [f"{k}=?" for k in update_data]
        vals = list(update_data.values()) + [pc_id]
        c.execute(f"UPDATE pcs SET {','.join(fields)} WHERE pc_id=?", vals)
    return {"ok": True}

@app.put("/api/pcs/{pc_id}/move")
def move_pc(pc_id: str, data: PcMove, user=Depends(get_current_user)):
    with db() as c:
        pc = c.execute("SELECT lab_id FROM pcs WHERE pc_id=?", (pc_id,)).fetchone()
        if not pc:
            raise HTTPException(404, "PC를 찾을 수 없습니다")
        check_lab_access(user, pc["lab_id"])
        c.execute("UPDATE pcs SET grid_row=?, grid_col=? WHERE pc_id=?",
                  (data.grid_row, data.grid_col, pc_id))
    return {"ok": True}

@app.delete("/api/pcs/{pc_id}")
def delete_pc(pc_id: str, user=Depends(get_current_user)):
    with db() as c:
        pc = c.execute("SELECT lab_id FROM pcs WHERE pc_id=?", (pc_id,)).fetchone()
        if not pc:
            raise HTTPException(404, "PC를 찾을 수 없습니다")
        check_lab_access(user, pc["lab_id"])
        c.execute("DELETE FROM security_scores WHERE ip_address IN (SELECT ip_address FROM pcs WHERE pc_id=?)", (pc_id,))
        c.execute("DELETE FROM pcs WHERE pc_id=?", (pc_id,))
    return {"ok": True}


# ── Scores API ──

@app.get("/api/scores")
def list_scores(user=Depends(get_current_user)):
    with db() as c:
        return {r["ip_address"]: r["security_score"]
                for r in c.execute("SELECT ip_address, security_score FROM security_scores").fetchall()}

@app.get("/api/upload-history")
def last_upload(user=Depends(get_current_user)):
    with db() as c:
        r = c.execute("SELECT * FROM upload_history ORDER BY upload_id DESC LIMIT 1").fetchone()
        return dict(r) if r else {}

@app.post("/api/upload-scores")
async def upload_scores_api(file: UploadFile = File(...), user=Depends(require_admin)):
    content = await file.read()
    df = pd.read_excel(io.BytesIO(content), header=1)
    if 'IP' not in df.columns or '보안점수' not in df.columns:
        raise HTTPException(400, "IP, 보안점수 컬럼이 필요합니다")
    sdf = df[df['보안점수'].notna() & df['IP'].notna()]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with db() as c:
        c.execute("DELETE FROM security_scores")
        registered = {r["ip_address"] for r in c.execute("SELECT ip_address FROM pcs").fetchall()}
        matched = unmatched = 0
        for _, row in sdf.iterrows():
            ip = str(row['IP']).strip()
            score = int(row['보안점수'])
            if ip in registered:
                c.execute("INSERT OR REPLACE INTO security_scores VALUES (?,?,?)", (ip, score, now))
                matched += 1
            else:
                unmatched += 1
        c.execute("INSERT INTO upload_history (upload_date,file_name,total_count,matched,unmatched) VALUES (?,?,?,?,?)",
                  (now, file.filename, len(sdf), matched, unmatched))
    return {"matched": matched, "unmatched": unmatched, "total": len(sdf)}


@app.post("/api/import-excel")
async def import_excel_api(file: UploadFile = File(...), user=Depends(require_admin)):
    content = await file.read()
    df = pd.read_excel(io.BytesIO(content), header=1)
    df2 = df.copy()
    df2['파트'] = df2['파트'].fillna('기타') if '파트' in df2.columns else '기타'
    df2 = df2[df2['IP'].notna() & (df2['IP'] != '')]
    df2['IP'] = df2['IP'].astype(str).str.strip()
    parts = df2['파트'].unique().tolist()
    if '기타' in parts:
        parts.remove('기타')
        parts.append('기타')
    with db() as c:
        c.execute("DELETE FROM security_scores")
        c.execute("DELETE FROM pcs")
        c.execute("DELETE FROM labs")
        for order, part in enumerate(parts):
            lab_id = part.replace(" ","_").lower()
            pp = df2[df2['파트']==part]
            cnt = len(pp)
            gc = min(8, cnt)
            gr = max(1, math.ceil(cnt/gc))
            c.execute("INSERT INTO labs VALUES (?,?,?,?,?)", (lab_id, part, gr, gc, order))
            for idx, (_, row) in enumerate(pp.iterrows()):
                r, col = idx//gc, idx%gc
                ip = str(row['IP']).strip()
                nm = []
                if pd.notna(row.get('성명')): nm.append(str(row['성명']))
                if pd.notna(row.get('세부위치')): nm.append(str(row['세부위치']))
                pc_name = " / ".join(nm) if nm else ip
                loc = str(row.get('설치위치','')) if pd.notna(row.get('설치위치')) else ''
                det = str(row.get('세부위치','')) if pd.notna(row.get('세부위치')) else ''
                pc_id = f"pc_{ip.replace('.','_')}"
                c.execute("INSERT OR IGNORE INTO pcs VALUES (?,?,?,?,?,?,?,?,?)",
                          (pc_id, ip, pc_name, lab_id, r, col, loc, det, ''))
        sdf = df[df['보안점수'].notna() & df['IP'].notna()] if '보안점수' in df.columns else pd.DataFrame()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        matched = 0
        if len(sdf) > 0:
            registered = {r["ip_address"] for r in c.execute("SELECT ip_address FROM pcs").fetchall()}
            for _, row in sdf.iterrows():
                ip = str(row['IP']).strip()
                if ip in registered:
                    c.execute("INSERT OR REPLACE INTO security_scores VALUES (?,?,?)",
                              (ip, int(row['보안점수']), now))
                    matched += 1
    return {"labs": len(parts), "pcs": len(df2), "scores_matched": matched}


# ── Stats ──

@app.get("/api/stats")
def stats(user=Depends(get_current_user)):
    with db() as c:
        if user["role"] == "admin":
            pcs = [dict(r) for r in c.execute("SELECT * FROM pcs").fetchall()]
        scores = {r["ip_address"]: r["security_score"]
                  for r in c.execute("SELECT ip_address, security_score FROM security_scores").fetchall()}
        total = len(pcs)
        ok = sum(1 for p in pcs if scores.get(p["ip_address"]) == 100)
        fail = sum(1 for p in pcs if p["ip_address"] in scores and scores[p["ip_address"]] < 100)
        return {"total": total, "ok": ok, "fail": fail, "none": total - ok - fail}
