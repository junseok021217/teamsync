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

app = FastAPI(title="TeamSync 실전 API", description="DISC 기반 공모전/팀플 매칭 및 단체 채팅 백엔드")

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
        is_seeking BOOLEAN DEFAULT 1,
        available_time_start TEXT DEFAULT '09:00',
        available_time_end TEXT DEFAULT '18:00'
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
        image_url TEXT,
        created_at TEXT NOT NULL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS project_applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        applicant_email TEXT NOT NULL,
        applicant_name TEXT NOT NULL,
        status TEXT DEFAULT 'pending'
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS project_members (
        project_id INTEGER NOT NULL,
        member_email TEXT NOT NULL,
        member_name TEXT NOT NULL,
        PRIMARY KEY (project_id, member_email)
    )
    """)
    conn.commit()
    conn.close()

init_db()

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
    available_time_start: Optional[str] = None
    available_time_end: Optional[str] = None

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
    image_url: Optional[str] = ""

def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(email: str) -> str:
    payload = {"sub": email, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)}
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
    except Exception:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")

@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h3>index.html 파일을 찾을 수 없습니다.</h3>"

@app.post("/api/auth/signup")
def signup(data: UserSignUp):
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO users (email, password_hash, name, age, major, education, disc_scores, preferred_roles)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (data.email, hash_pw(data.password), data.name, data.age, data.major, data.education, json.dumps({"D": 0, "I": 0, "S": 0, "C": 0}), json.dumps([]))
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="이미 가입된 이메일입니다.")
    finally:
        conn.close()
    return {"message": f"{data.name}님, 회원가입이 완료되었습니다."}

@app.post("/api/auth/login")
def login(data: UserLogin):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (data.email,)).fetchone()
    conn.close()
    if not user or user["password_hash"] != hash_pw(data.password):
        raise HTTPException(status_code=401, detail="이메일 또는 비밀번호가 일치하지 않습니다.")
    token = create_token(data.email)
    return {"access_token": token, "token_type": "bearer", "name": user["name"], "email": user["email"]}

@app.get("/api/users/me")
def read_my_profile(current_user: dict = Depends(get_current_user)):
    current_user.pop("password_hash", None)
    current_user["disc_scores"] = json.loads(current_user["disc_scores"] or "{}")
    current_user["preferred_roles"] = json.loads(current_user["preferred_roles"] or "[]")
    return current_user

@app.put("/api/users/me")
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

@app.get("/api/disc/questions")
def get_disc_questions():
    # 40문항 자체 생성 및 반환 (파일 누락 방지)
    questions = [{"id": str(i), "question": f"DISC 행동유형 진단 문항 {i}번입니다. 평소 나의 성향과 얼마나 일치합니까?", "style": ["D", "I", "S", "C"][i % 4]} for i in range(1, 41)]
    return {"total": 40, "questions": questions}

@app.post("/api/disc/submit")
def submit_disc(payload: DiscSubmit, current_user: dict = Depends(get_current_user)):
    scores = {"D": 0, "I": 0, "S": 0, "C": 0}
    for q_id, val in payload.answers.items():
        idx = int(q_id) % 4
        style = ["D", "I", "S", "C"][idx]
        scores[style] += val

    primary_type = max(scores, key=scores.get)
    conn = get_db()
    conn.execute(
        "UPDATE users SET disc_type = ?, disc_scores = ? WHERE email = ?",
        (primary_type, json.dumps(scores), current_user["email"])
    )
    conn.commit()
    conn.close()
    return {"message": "반영되었습니다.", "disc_type": primary_type, "disc_scores": scores}

@app.get("/api/projects")
def get_projects():
    conn = get_db()
    rows = conn.execute("SELECT p.*, u.name as author_name FROM projects p JOIN users u ON p.author_email = u.email ORDER BY p.id DESC").fetchall()
    conn.close()
    projects = []
    for r in rows:
        p = dict(r)
        p["needed_roles"] = json.loads(p["needed_roles"] or "[]")
        p["needed_disc"] = json.loads(p["needed_disc"] or "[]")
        projects.append(p)
    return projects

@app.post("/api/projects")
def create_project(proj: ProjectCreate, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO projects 
           (author_email, category, title, description, meeting_type, needed_roles, needed_disc, commitment_level, available_time, image_url, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            current_user["email"], proj.category, proj.title, proj.description,
            proj.meeting_type,
            json.dumps(proj.needed_roles, ensure_ascii=False),
            json.dumps(proj.needed_disc, ensure_ascii=False),
            proj.commitment_level, proj.available_time, proj.image_url,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        )
    )
    project_id = cursor.lastrowid
    cursor.execute("INSERT OR IGNORE INTO project_members (project_id, member_email, member_name) VALUES (?, ?, ?)", 
                   (project_id, current_user["email"], current_user["name"]))
    conn.commit()
    conn.close()
    return {"message": "등록되었습니다.", "project_id": project_id}

@app.post("/api/projects/{project_id}/apply")
def apply_project(project_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404, detail="공모전 글을 찾을 수 없습니다.")
    if proj["author_email"] == current_user["email"]:
        conn.close()
        raise HTTPException(status_code=400, detail="본인이 작성한 공모전에는 지원할 수 없습니다.")
    
    existing = conn.execute("SELECT * FROM project_applications WHERE project_id = ? AND applicant_email = ?", (project_id, current_user["email"])).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="이미 지원한 공모전입니다.")

    conn.execute("INSERT INTO project_applications (project_id, applicant_email, applicant_name, status) VALUES (?, ?, ?, 'pending')",
                 (project_id, current_user["email"], current_user["name"]))
    conn.commit()
    conn.close()
    return {"message": "공모전 지원이 완료되었습니다!"}

@app.get("/api/projects/{project_id}/applications")
def get_project_applications(project_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj or proj["author_email"] != current_user["email"]:
        conn.close()
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    rows = conn.execute("SELECT * FROM project_applications WHERE project_id = ? AND status = 'pending'", (project_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/applications/{app_id}/action")
def application_action(app_id: int, action_data: dict, current_user: dict = Depends(get_current_user)):
    action = action_data.get("action")
    conn = get_db()
    app_row = conn.execute("SELECT * FROM project_applications WHERE id = ?", (app_id,)).fetchone()
    if not app_row:
        conn.close()
        raise HTTPException(status_code=404, detail="지원 내역을 찾을 수 없습니다.")
    
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (app_row["project_id"],)).fetchone()
    if proj["author_email"] != current_user["email"]:
        conn.close()
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    if action == "accept":
        conn.execute("UPDATE project_applications SET status = 'accepted' WHERE id = ?", (app_id,))
        conn.execute("INSERT OR IGNORE INTO project_members (project_id, member_email, member_name) VALUES (?, ?, ?)",
                     (app_row["project_id"], app_row["applicant_email"], app_row["applicant_name"]))
        conn.commit()
        conn.close()
        return {"message": "지원을 수락하였습니다. 팀원 채팅방에 참여됩니다."}
    elif action == "reject":
        conn.execute("UPDATE project_applications SET status = 'rejected' WHERE id = ?", (app_id,))
        conn.commit()
        conn.close()
        return {"message": "지원을 거절하였습니다."}
    else:
        conn.close()
        raise HTTPException(status_code=400, detail="잘못된 요청입니다.")

@app.get("/api/my-teams")
def get_my_teams(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute("""
        SELECT p.id, p.title, p.category FROM project_members pm
        JOIN projects p ON pm.project_id = p.id
        WHERE pm.member_email = ?
    """, (current_user["email"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/projects/{project_id}/members")
def get_project_members(project_id: int):
    conn = get_db()
    rows = conn.execute("SELECT member_name, member_email FROM project_members WHERE project_id = ?", (project_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

class ConnectionManager:
    def __init__(self):
        self.rooms: Dict[int, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, project_id: int):
        await websocket.accept()
        if project_id not in self.rooms:
            self.rooms[project_id] = []
        self.rooms[project_id].append(websocket)

    def disconnect(self, websocket: WebSocket, project_id: int):
        if project_id in self.rooms:
            if websocket in self.rooms[project_id]:
                self.rooms[project_id].remove(websocket)

    async def broadcast_to_room(self, project_id: int, message: str):
        if project_id in self.rooms:
            for connection in self.rooms[project_id]:
                await connection.send_text(message)

manager = ConnectionManager()

@app.websocket("/ws/chat/{project_id}/{user_name}")
async def websocket_chat_endpoint(websocket: WebSocket, project_id: int, user_name: str):
    await manager.connect(websocket, project_id)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast_to_room(project_id, f"[{user_name}]: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket, project_id)
