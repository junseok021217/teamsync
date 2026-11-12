import json
import sqlite3
import hashlib
import datetime
from typing import Optional, List, Dict
from fastapi import FastAPI, HTTPException, Depends, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import os
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import jwt

app = FastAPI(title="TeamSync 실전 API", description="DISC 기반 공모전/팀플 매칭 및 실시간 채팅 백엔드")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "teamsync-secret-key-change-in-prod"
DB_PATH = "teamsync.db"

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        age INTEGER,
        major TEXT,
        education TEXT,
        certifications TEXT,
        awards TEXT,
        portfolio_url TEXT,
        disc_type TEXT,
        disc_scores TEXT,
        can_present BOOLEAN DEFAULT 1,
        preferred_roles TEXT,
        is_seeking BOOLEAN DEFAULT 1
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author_email TEXT NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        meeting_type TEXT NOT NULL,
        needed_roles TEXT NOT NULL,
        needed_disc TEXT NOT NULL,
        commitment_level TEXT,
        available_time TEXT,
        created_at TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ----------------------------------------------------
# Pydantic 모델 정의
# ----------------------------------------------------
class UserSignUp(BaseModel):
    email: EmailStr
    password: str
    name: str
    age: Optional[int] = None
    major: Optional[str] = ""
    education: Optional[str] = ""

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    age: Optional[int] = None
    major: Optional[str] = None
    education: Optional[str] = None
    certifications: Optional[str] = None
    awards: Optional[str] = None
    portfolio_url: Optional[str] = None
    can_present: Optional[bool] = None
    preferred_roles: Optional[List[str]] = None
    is_seeking: Optional[bool] = None

class DiscSubmit(BaseModel):
    answers: Dict[str, int]

class ProjectCreate(BaseModel):
    category: str
    title: str
    description: str
    meeting_type: str
    needed_roles: List[str]
    needed_disc: List[str]
    commitment_level: str
    available_time: str

class FriendRequest(BaseModel):
    user_id: str
    target_id: str

class FriendAction(BaseModel):
    request_id: int

# ----------------------------------------------------
# 유틸리티 및 인증 함수
# ----------------------------------------------------
def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(email: str) -> str:
    payload = {
        "sub": email,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def get_current_user(authorization: str = Header(..., description="Bearer <토큰>")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="토큰 형식이 올바르지 않습니다.")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email = payload.get("sub")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()
        if not user:
            raise HTTPException(status_code=401, detail="존재하지 않는 사용자입니다.")
        return dict(user)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="토큰이 만료되었습니다.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")

# ----------------------------------------------------
# 프론트엔드 HTML 서빙
# ----------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h3>index.html 파일을 찾을 수 없습니다.</h3>"

# ----------------------------------------------------
# 회원가입 / 로그인 / 프로필 API
# ----------------------------------------------------
@app.post("/api/auth/signup", summary="회원가입")
def signup(data: UserSignUp):
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO users (email, password_hash, name, age, major, education, disc_scores, preferred_roles)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                data.email, hash_pw(data.password), data.name, data.age,
                data.major, data.education,
                json.dumps({"D": 0, "I": 0, "S": 0, "C": 0}),
                json.dumps([])
            )
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="이미 가입된 이메일입니다.")
    finally:
        conn.close()
    return {"message": f"{data.name}님, 회원가입이 완료되었습니다."}

@app.post("/api/auth/login", summary="로그인")
def login(data: UserLogin):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (data.email,)).fetchone()
    conn.close()
    if not user or user["password_hash"] != hash_pw(data.password):
        raise HTTPException(status_code=401, detail="이메일 또는 비밀번호가 일치하지 않습니다.")
    token = create_token(data.email)
    return {"access_token": token, "token_type": "bearer", "name": user["name"]}

@app.get("/api/users/me", summary="마이페이지 조회")
def read_my_profile(current_user: dict = Depends(get_current_user)):
    current_user.pop("password_hash", None)
    current_user["disc_scores"] = json.loads(current_user["disc_scores"] or "{}")
    current_user["preferred_roles"] = json.loads(current_user["preferred_roles"] or "[]")
    return current_user

@app.put("/api/users/me", summary="프로필 수정")
def update_my_profile(update: ProfileUpdate, current_user: dict = Depends(get_current_user)):
    fields = update.dict(exclude_unset=True)
    if not fields:
        return {"message": "수정할 내용이 없습니다."}
    if "preferred_roles" in fields:
        fields["preferred_roles"] = json.dumps(fields["preferred_roles"], ensure_ascii=False)
    set_clause = ", ".join([f"{k} = ?" for k in fields.keys()])
    values = list(fields.values()) + [current_user["email"]]
    conn = get_db()
    conn.execute(f"UPDATE users SET {set_clause} WHERE email = ?", values)
    conn.commit()
    conn.close()
    return {"message": "프로필이 수정되었습니다."}

# ----------------------------------------------------
# DISC 검사 API
# ----------------------------------------------------
@app.get("/api/disc/questions", summary="DISC 40문항 불러오기")
def get_disc_questions():
    try:
        with open("disc_items.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        items = data if isinstance(data, list) else data.get("items", [])
        selected = []
        for style in ["D", "I", "S", "C"]:
            style_items = [item for item in items if isinstance(item, dict) and item.get("style") == style][:10]
            selected.extend(style_items)
        if not selected and len(items) > 0:
            selected = items[:40]
        return {"total": len(selected), "questions": selected}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="disc_items.json 파일이 없습니다.")

@app.post("/api/disc/submit", summary="DISC 검사 제출")
def submit_disc(payload: DiscSubmit, current_user: dict = Depends(get_current_user)):
    with open("disc_items.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    items = data if isinstance(data, list) else data.get("items", [])
    items_map = {item["id"]: item for item in items if isinstance(item, dict) and "id" in item}

    scores = {"D": 0, "I": 0, "S": 0, "C": 0}
    for q_id, raw_val in payload.answers.items():
        if q_id in items_map:
            item = items_map[q_id]
            score = raw_val if item.get("keyed", 1) == 1 else (6 - raw_val)
            if item.get("style") in scores:
                scores[item["style"]] += score

    primary_type = max(scores, key=scores.get)
    conn = get_db()
    conn.execute(
        "UPDATE users SET disc_type = ?, disc_scores = ? WHERE email = ?",
        (primary_type, json.dumps(scores), current_user["email"])
    )
    conn.commit()
    conn.close()
    return {"message": "반영되었습니다.", "disc_type": primary_type, "disc_scores": scores}

# ----------------------------------------------------
# 공모전 및 팀원 매칭 API
# ----------------------------------------------------
@app.get("/api/projects", summary="모집글 목록 조회")
def get_projects():
    conn = get_db()
    rows = conn.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()
    conn.close()
    projects = []
    for r in rows:
        p = dict(r)
        p["needed_roles"] = json.loads(p["needed_roles"] or "[]")
        p["needed_disc"] = json.loads(p["needed_disc"] or "[]")
        projects.append(p)
    return projects

@app.post("/api/projects", summary="모집글 등록")
def create_project(proj: ProjectCreate, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    conn.execute(
        """INSERT INTO projects 
           (author_email, category, title, description, meeting_type, needed_roles, needed_disc, commitment_level, available_time, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            current_user["email"], proj.category, proj.title, proj.description,
            proj.meeting_type,
            json.dumps(proj.needed_roles, ensure_ascii=False),
            json.dumps(proj.needed_disc, ensure_ascii=False),
            proj.commitment_level, proj.available_time,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        )
    )
    conn.commit()
    conn.close()
    return {"message": "등록되었습니다."}

@app.get("/api/projects/{project_id}/recommend-members", summary="맞춤 팀원 추천")
def recommend_members(project_id: int):
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    needed_disc = json.loads(proj["needed_disc"])
    needed_roles = json.loads(proj["needed_roles"])

    candidates = conn.execute(
        "SELECT email, name, major, disc_type, disc_scores, preferred_roles, can_present, portfolio_url FROM users WHERE is_seeking = 1 AND email != ?",
        (proj["author_email"],)
    ).fetchall()
    conn.close()

    recommendations = []
    for c in candidates:
        c_dict = dict(c)
        c_roles = json.loads(c_dict["preferred_roles"] or "[]")
        match_score = 0
        reasons = []
        if c_dict["disc_type"] in needed_disc:
            match_score += 50
            reasons.append(f"성향({c_dict['disc_type']}형) 일치")
        matched_roles = set(needed_roles) & set(c_roles)
        if matched_roles:
            match_score += 30 * len(matched_roles)
            reasons.append(f"역할 일치({', '.join(matched_roles)})")
        if match_score > 0:
            c_dict["preferred_roles"] = c_roles
            c_dict["disc_scores"] = json.loads(c_dict["disc_scores"] or "{}")
            c_dict["match_score"] = match_score
            c_dict["match_reasons"] = reasons
            recommendations.append(c_dict)

    recommendations.sort(key=lambda x: x["match_score"], reverse=True)
    return {"project_title": proj["title"], "recommended_users": recommendations}

# ----------------------------------------------------
# 친구 추가 및 실시간 웹소켓 채팅 API
# ----------------------------------------------------
friend_requests_db = {}
friends_db = {}
request_counter = 1

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self,
