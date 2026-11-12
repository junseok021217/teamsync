import json
import sqlite3
import hashlib
import datetime
import os
from typing import Optional, List, Dict
from fastapi import FastAPI, HTTPException, Depends, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
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
        status TEXT DEFAULT 'pending',
        created_at TEXT
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
    cur.execute("""
    CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        sender_email TEXT NOT NULL,
        sender_name TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    # 기존 DB 파일 호환을 위한 안전한 컬럼 자동 추가 (마이그레이션)
    user_cols = [row["name"] for row in cur.execute("PRAGMA table_info(users)").fetchall()]
    if "available_time_start" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN available_time_start TEXT DEFAULT '09:00'")
    if "available_time_end" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN available_time_end TEXT DEFAULT '18:00'")

    proj_cols = [row["name"] for row in cur.execute("PRAGMA table_info(projects)").fetchall()]
    if "image_url" not in proj_cols:
        cur.execute("ALTER TABLE projects ADD COLUMN image_url TEXT DEFAULT ''")

    app_cols = [row["name"] for row in cur.execute("PRAGMA table_info(project_applications)").fetchall()]
    if "created_at" not in app_cols:
        cur.execute("ALTER TABLE project_applications ADD COLUMN created_at TEXT DEFAULT ''")

    # 기존 생성된 프로젝트 작성자가 project_members에 누락된 경우 자동 등록
    cur.execute("""
        INSERT OR IGNORE INTO project_members (project_id, member_email, member_name)
        SELECT p.id, p.author_email, COALESCE(u.name, '작성자')
        FROM projects p
        LEFT JOIN users u ON p.author_email = u.email
    """)

    conn.commit()
    conn.close()

init_db()

# ----------------------------------------------------
# Pydantic 모델
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
    available_time_start: Optional[str] = None
    available_time_end: Optional[str] = None

class DiscSubmit(BaseModel):
    answers: Dict[str, int]

class ProjectCreate(BaseModel):
    category: str
    title: str
    description: str
    meeting_type: str
    needed_roles: List[str] = []
    needed_disc: List[str] = []
    commitment_level: Optional[str] = ""
    available_time: Optional[str] = ""
    image_url: Optional[str] = ""

class ChatMessageCreate(BaseModel):
    message: str

# ----------------------------------------------------
# 인증 및 유틸 함수
# ----------------------------------------------------
def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(email: str) -> str:
    payload = {
        "sub": email,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="로그인이 필요합니다.")
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
        raise HTTPException(status_code=401, detail="인증 세션이 만료되었습니다. 다시 로그인해 주세요.")

@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h3>index.html 파일을 찾을 수 없습니다.</h3>"

# ----------------------------------------------------
# 회원 및 프로필 API
# ----------------------------------------------------
@app.post("/api/auth/signup")
def signup(data: UserSignUp):
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO users (email, password_hash, name, age, major, education, disc_scores, preferred_roles, available_time_start, available_time_end)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, '09:00', '18:00')""",
            (
                data.email, hash_pw(data.password), data.name, data.age,
                data.major or "", data.education or "",
                json.dumps({"D": 0, "I": 0, "S": 0, "C": 0}),
                json.dumps([])
            )
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="이미 가입된 이메일입니다.")
    finally:
        conn.close()
    return {"message": f"{data.name}님, 회원가입이 완료되었습니다!"}

@app.post("/api/auth/login")
def login(data: UserLogin):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (data.email,)).fetchone()
    conn.close()
    if not user or user["password_hash"] != hash_pw(data.password):
        raise HTTPException(status_code=401, detail="이메일 또는 비밀번호가 일치하지 않습니다.")
    token = create_token(data.email)
    return {
        "access_token": token,
        "token_type": "bearer",
        "name": user["name"],
        "email": user["email"]
    }

@app.get("/api/users/me")
def read_my_profile(current_user: dict = Depends(get_current_user)):
    current_user.pop("password_hash", None)
    try:
        current_user["disc_scores"] = json.loads(current_user.get("disc_scores") or '{"D":0,"I":0,"S":0,"C":0}')
    except Exception:
        current_user["disc_scores"] = {"D": 0, "I": 0, "S": 0, "C": 0}
    try:
        current_user["preferred_roles"] = json.loads(current_user.get("preferred_roles") or "[]")
    except Exception:
        current_user["preferred_roles"] = []
    current_user["available_time_start"] = current_user.get("available_time_start") or "09:00"
    current_user["available_time_end"] = current_user.get("available_time_end") or "18:00"
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
    if "name" in fields and fields["name"]:
        conn.execute("UPDATE project_members SET member_name = ? WHERE member_email = ?", (fields["name"], current_user["email"]))
    conn.commit()
    conn.close()
    return {"message": "프로필이 성공적으로 저장되었습니다."}

# ----------------------------------------------------
# DISC 40문항 진단 API (파일 없을 시 내장 40문항 자동 사용)
# ----------------------------------------------------
DEFAULT_DISC_QUESTIONS = [
    # D (주도형) 10문항
    {"id": "D1", "style": "D", "keyed": 1, "question": "팀 프로젝트에서 목표를 빠르게 설정하고 주도적으로 이끄는 편이다."},
    {"id": "D2", "style": "D", "keyed": 1, "question": "어려운 결정이 필요할 때 망설이지 않고 결단을 내린다."},
    {"id": "D3", "style": "D", "keyed": 1, "question": "경쟁적인 상황에서 오히려 더 큰 동기와 에너지를 얻는다."},
    {"id": "D4", "style": "D", "keyed": 1, "question": "과정보다 최종 결과와 성과 달성을 가장 중요하게 생각한다."},
    {"id": "D5", "style": "D", "keyed": 1, "question": "회의가 길어지면 핵심 결론부터 빠르게 도출하려고 한다."},
    {"id": "D6", "style": "D", "keyed": 1, "question": "새로운 도전이나 리스크가 있는 주제를 맡는 것을 두려워하지 않는다."},
    {"id": "D7", "style": "D", "keyed": 1, "question": "내 의견을 명확하고 직설적으로 표현하는 편이다."},
    {"id": "D8", "style": "D", "keyed": 1, "question": "일정이 지연되면 팀원들을 독려하여 속도를 높인다."},
    {"id": "D9", "style": "D", "keyed": 1, "question": "팀장이나 프로젝트 총괄 역할을 맡는 것이 자연스럽다."},
    {"id": "D10", "style": "D", "keyed": 1, "question": "문제 발생 시 즉각적으로 해결책을 실행에 옮긴다."},
    # I (사교형) 10문항
    {"id": "I1", "style": "I", "keyed": 1, "question": "처음 만나는 팀원들과도 어색함 없이 대화를 주도하며 분위기를 띄운다."},
    {"id": "I2", "style": "I", "keyed": 1, "question": "브레인스토밍에서 창의적이고 참신한 아이디어를 자주 내놓는다."},
    {"id": "I3", "style": "I", "keyed": 1, "question": "청중 앞에서 프로젝트를 발표하거나 설득하는 역할에 자신이 있다."},
    {"id": "I4", "style": "I", "keyed": 1, "question": "팀원들을 칭찬하고 긍정적인 피드백을 주는 것을 좋아한다."},
    {"id": "I5", "style": "I", "keyed": 1, "question": "딱딱한 회의보다는 자유롭고 활발한 소통 환경을 선호한다."},
    {"id": "I6", "style": "I", "keyed": 1, "question": "시각적으로 돋보이는 발표자료(PPT)나 스토리텔링 구성에 흥미가 있다."},
    {"id": "I7", "style": "I", "keyed": 1, "question": "주변 사람들과 네트워킹하고 협업하는 과정에서 큰 즐거움을 느낀다."},
    {"id": "I8", "style": "I", "keyed": 1, "question": "팀 분위기가 침체되었을 때 유머나 밝은 에너지로 전환시킨다."},
    {"id": "I9", "style": "I", "keyed": 1, "question": "세부적인 규칙에 얽매이기보다 유연하게 대처하는 편이다."},
    {"id": "I10", "style": "I", "keyed": 1, "question": "다른 사람의 호응과 인정을 받을 때 업무 효율이 크게 오른다."},
    # S (안정형) 10문항
    {"id": "S1", "style": "S", "keyed": 1, "question": "팀원들의 의견을 끝까지 경청하고 갈등을 원만하게 중재한다."},
    {"id": "S2", "style": "S", "keyed": 1, "question": "정해진 계획과 절차에 따라 꾸준히 맡은 바를 완수한다."},
    {"id": "S3", "style": "S", "keyed": 1, "question": "내가 돋보이기보다 팀 전체의 화합과 협력을 우선시한다."},
    {"id": "S4", "style": "S", "keyed": 1, "question": "팀원이 어려움을 겪을 때 기꺼이 돕고 지원하는 역할이 편하다."},
    {"id": "S5", "style": "S", "keyed": 1, "question": "급격한 변화보다는 예측 가능하고 안정적인 일정 관리를 선호한다."},
    {"id": "S6", "style": "S", "keyed": 1, "question": "반복적이거나 끈기가 필요한 자료 정리 작업도 성실히 해낸다."},
    {"id": "S7", "style": "S", "keyed": 1, "question": "감정 기복이 적고 마감 직전에도 차분함을 유지한다."},
    {"id": "S8", "style": "S", "keyed": 1, "question": "약속 시간과 회의 일정을 철저히 지키는 편이다."},
    {"id": "S9", "style": "S", "keyed": 1, "question": "경쟁보다는 모두가 만족할 수 있는 합의점을 찾으려 노력한다."},
    {"id": "S10", "style": "S", "keyed": 1, "question": "신뢰할 수 있는 든든한 서포터라는 평가를 자주 듣는다."},
    # C (신중형) 10문항
    {"id": "C1", "style": "C", "keyed": 1, "question": "주장을 펼칠 때 반드시 객관적인 데이터와 근거 자료를 확인한다."},
    {"id": "C2", "style": "C", "keyed": 1, "question": "보고서나 발표자료의 오탈자, 논리적 오류를 꼼꼼하게 검수한다."},
    {"id": "C3", "style": "C", "keyed": 1, "question": "프로젝트 시작 전 세부적인 타임라인과 체크리스트를 작성한다."},
    {"id": "C4", "style": "C", "keyed": 1, "question": "감이나 직관보다 체계적인 분석과 통계 자료를 신뢰한다."},
    {"id": "C5", "style": "C", "keyed": 1, "question": "자료조사 및 레퍼런스 분석 역할을 맡았을 때 높은 완성도를 보인다."},
    {"id": "C6", "style": "C", "keyed": 1, "question": "예상되는 문제점이나 리스크를 사전에 파악하여 대비책을 세운다."},
    {"id": "C7", "style": "C", "keyed": 1, "question": "업무 분장과 평가 기준이 명확할 때 가장 효율적으로 일한다."},
    {"id": "C8", "style": "C", "keyed": 1, "question": "결정을 내리기 전에 충분한 정보를 수집하고 신중하게 검토한다."},
    {"id": "C9", "style": "C", "keyed": 1, "question": "결과물의 품질과 정확성에 대해 높은 기준을 가지고 있다."},
    {"id": "C10", "style": "C", "keyed": 1, "question": "복잡한 문제를 논리적으로 구조화하여 정리하는 것에 능숙하다."}
]

def load_disc_40_items():
    if os.path.exists("disc_items.json"):
        try:
            with open("disc_items.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            items = data if isinstance(data, list) else data.get("items", [])
            selected = []
            for style in ["D", "I", "S", "C"]:
                style_items = [item for item in items if isinstance(item, dict) and item.get("style") == style][:10]
                selected.extend(style_items)
            if len(selected) >= 20:
                for idx, it in enumerate(selected):
                    it["id"] = str(it.get("id", f"Q{idx+1}"))
                    if "question" not in it and "text" in it:
                        it["question"] = it["text"]
                return selected
        except Exception:
            pass
    return DEFAULT_DISC_QUESTIONS

@app.get("/api/disc/questions")
def get_disc_questions():
    items = load_disc_40_items()
    return {"total": len(items), "questions": items}

@app.post("/api/disc/submit")
def submit_disc(payload: DiscSubmit, current_user: dict = Depends(get_current_user)):
    items = load_disc_40_items()
    items_map = {str(item["id"]): item for item in items}

    scores = {"D": 0, "I": 0, "S": 0, "C": 0}
    for q_id, raw_val in payload.answers.items():
        q_key = str(q_id)
        val = int(raw_val)
        if q_key in items_map:
            item = items_map[q_key]
            score = val if item.get("keyed", 1) == 1 else (6 - val)
            style = item.get("style", "C")
            if style in scores:
                scores[style] += score

    primary_type = max(scores, key=scores.get)
    conn = get_db()
    conn.execute(
        "UPDATE users SET disc_type = ?, disc_scores = ? WHERE email = ?",
        (primary_type, json.dumps(scores), current_user["email"])
    )
    conn.commit()
    conn.close()
    return {"message": "DISC 진단 결과가 프로필에 반영되었습니다!", "disc_type": primary_type, "disc_scores": scores}

# ----------------------------------------------------
# 공모전 모집글 및 맞춤 추천 API
# ----------------------------------------------------
@app.get("/api/projects")
def get_projects():
    conn = get_db()
    rows = conn.execute("""
        SELECT p.*, COALESCE(u.name, p.author_email) as author_name, u.disc_type as author_disc
        FROM projects p
        LEFT JOIN users u ON p.author_email = u.email
        ORDER BY p.id DESC
    """).fetchall()

    apps = conn.execute("SELECT project_id, applicant_email, status FROM project_applications").fetchall()
    members = conn.execute("SELECT project_id, member_email, member_name FROM project_members").fetchall()
    conn.close()

    app_map = {}
    for a in apps:
        pid = a["project_id"]
        if pid not in app_map:
            app_map[pid] = []
        app_map[pid].append(dict(a))

    mem_map = {}
    for m in members:
        pid = m["project_id"]
        if pid not in mem_map:
            mem_map[pid] = []
        mem_map[pid].append(dict(m))

    projects = []
    for r in rows:
        p = dict(r)
        try:
            p["needed_roles"] = json.loads(p["needed_roles"] or "[]")
        except Exception:
            p["needed_roles"] = []
        try:
            p["needed_disc"] = json.loads(p["needed_disc"] or "[]")
        except Exception:
            p["needed_disc"] = []
        p["applications"] = app_map.get(p["id"], [])
        p["members"] = mem_map.get(p["id"], [])
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
            proj.commitment_level or "", proj.available_time or "", proj.image_url or "",
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        )
    )
    project_id = cursor.lastrowid
    cursor.execute(
        "INSERT OR IGNORE INTO project_members (project_id, member_email, member_name) VALUES (?, ?, ?)",
        (project_id, current_user["email"], current_user["name"])
    )
    conn.commit()
    conn.close()
    return {"message": "모집글이 등록되었으며 팀 채팅방이 생성되었습니다!", "project_id": project_id}

@app.delete("/api/projects/{project_id}")
def delete_project(project_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404, detail="모집글을 찾을 수 없습니다.")
    if proj["author_email"] != current_user["email"]:
        conn.close()
        raise HTTPException(status_code=403, detail="작성자만 삭제할 수 있습니다.")
    conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    conn.execute("DELETE FROM project_applications WHERE project_id = ?", (project_id,))
    conn.execute("DELETE FROM project_members WHERE project_id = ?", (project_id,))
    conn.execute("DELETE FROM chat_messages WHERE project_id = ?", (project_id,))
    conn.commit()
    conn.close()
    return {"message": "모집글이 삭제되었습니다."}

@app.get("/api/projects/{project_id}/recommend-members")
def recommend_members(project_id: int):
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    needed_disc = json.loads(proj["needed_disc"] or "[]")
    needed_roles = json.loads(proj["needed_roles"] or "[]")

    candidates = conn.execute(
        """SELECT email, name, major, disc_type, disc_scores, preferred_roles, can_present,
                  portfolio_url, available_time_start, available_time_end
           FROM users WHERE is_seeking = 1 AND email != ?""",
        (proj["author_email"],)
    ).fetchall()
    conn.close()

    recommendations = []
    for c in candidates:
        c_dict = dict(c)
        c_roles = json.loads(c_dict["preferred_roles"] or "[]")
        match_score = 0
        reasons = []
        if c_dict.get("disc_type") and c_dict["disc_type"] in needed_disc:
            match_score += 50
            reasons.append(f"선호 성향({c_dict['disc_type']}형) 일치")
        matched_roles = set(needed_roles) & set(c_roles)
        if matched_roles:
            match_score += 30 * len(matched_roles)
            reasons.append(f"희망 역할({', '.join(matched_roles)}) 일치")
        if match_score == 0 and c_dict.get("disc_type"):
            match_score = 20
            reasons.append("구직 중인 활성 팀원")
        if match_score > 0:
            c_dict["preferred_roles"] = c_roles
            c_dict["disc_scores"] = json.loads(c_dict["disc_scores"] or "{}")
            c_dict["match_score"] = min(match_score, 100)
            c_dict["match_reasons"] = reasons
            recommendations.append(c_dict)

    recommendations.sort(key=lambda x: x["match_score"], reverse=True)
    return {"project_title": proj["title"], "recommended_users": recommendations}

# ----------------------------------------------------
# 공모전 지원 및 수락/거절 API
# ----------------------------------------------------
@app.post("/api/projects/{project_id}/apply")
def apply_project(project_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404, detail="공모전 글을 찾을 수 없습니다.")
    if proj["author_email"] == current_user["email"]:
        conn.close()
        raise HTTPException(status_code=400, detail="본인이 작성한 모집글에는 지원할 수 없습니다.")

    existing = conn.execute(
        "SELECT * FROM project_applications WHERE project_id = ? AND applicant_email = ?",
        (project_id, current_user["email"])
    ).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail=f"이미 지원하신 모집글입니다. (현재 상태: {existing['status']})")

    conn.execute(
        "INSERT INTO project_applications (project_id, applicant_email, applicant_name, status, created_at) VALUES (?, ?, ?, 'pending', ?)",
        (project_id, current_user["email"], current_user["name"], datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
    )
    conn.commit()
    conn.close()
    return {"message": "공모전 지원이 완료되었습니다! 작성자가 수락하면 팀 채팅방에 초대됩니다."}

@app.get("/api/projects/{project_id}/applications")
def get_project_applications(project_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj or proj["author_email"] != current_user["email"]:
        conn.close()
        raise HTTPException(status_code=403, detail="모집글 작성자만 조회할 수 있습니다.")

    rows = conn.execute("""
        SELECT pa.*, u.major, u.disc_type, u.preferred_roles, u.can_present,
               u.available_time_start, u.available_time_end, u.portfolio_url
        FROM project_applications pa
        LEFT JOIN users u ON pa.applicant_email = u.email
        WHERE pa.project_id = ?
        ORDER BY pa.id DESC
    """, (project_id,)).fetchall()
    conn.close()

    result = []
    for r in rows:
        d = dict(r)
        try:
            d["preferred_roles"] = json.loads(d.get("preferred_roles") or "[]")
        except Exception:
            d["preferred_roles"] = []
        result.append(d)
    return result

@app.post("/api/applications/{app_id}/action")
def application_action(app_id: int, action_data: dict, current_user: dict = Depends(get_current_user)):
    action = action_data.get("action")
    conn = get_db()
    app_row = conn.execute("SELECT * FROM project_applications WHERE id = ?", (app_id,)).fetchone()
    if not app_row:
        conn.close()
        raise HTTPException(status_code=404, detail="지원 내역을 찾을 수 없습니다.")

    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (app_row["project_id"],)).fetchone()
    if not proj or proj["author_email"] != current_user["email"]:
        conn.close()
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    if action == "accept":
        conn.execute("UPDATE project_applications SET status = 'accepted' WHERE id = ?", (app_id,))
        conn.execute(
            "INSERT OR IGNORE INTO project_members (project_id, member_email, member_name) VALUES (?, ?, ?)",
            (proj["id"], current_user["email"], current_user["name"])
        )
        conn.execute(
            "INSERT OR IGNORE INTO project_members (project_id, member_email, member_name) VALUES (?, ?, ?)",
            (app_row["project_id"], app_row["applicant_email"], app_row["applicant_name"])
        )
        # 시스템 환영 메시지 기록
        now_str = datetime.datetime.now().strftime("%H:%M")
        sys_msg = f"🎉 {app_row['applicant_name']}님이 팀에 합류했습니다!"
        conn.execute(
            "INSERT INTO chat_messages (project_id, sender_email, sender_name, message, created_at) VALUES (?, 'system', '알림', ?, ?)",
            (app_row["project_id"], sys_msg, now_str)
        )
        conn.commit()
        conn.close()
        return {"message": f"{app_row['applicant_name']}님의 지원을 수락했습니다! 이제 팀 단체 채팅방에서 대화할 수 있습니다.", "status": "accepted"}
    elif action == "reject":
        conn.execute("UPDATE project_applications SET status = 'rejected' WHERE id = ?", (app_id,))
        conn.execute(
            "DELETE FROM project_members WHERE project_id = ? AND member_email = ?",
            (app_row["project_id"], app_row["applicant_email"])
        )
        conn.commit()
        conn.close()
        return {"message": f"{app_row['applicant_name']}님의 지원을 거절했습니다.", "status": "rejected"}
    else:
        conn.close()
        raise HTTPException(status_code=400, detail="올바르지 않은 요청입니다.")

# ----------------------------------------------------
# 팀 단체 채팅방 (DB 저장 + REST + WebSocket 하이브리드)
# ----------------------------------------------------
@app.get("/api/my-teams")
def get_my_teams(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    # 작성자 본인 프로젝트가 누락되었을 경우를 대비해 보정
    conn.execute("""
        INSERT OR IGNORE INTO project_members (project_id, member_email, member_name)
        SELECT id, author_email, ? FROM projects WHERE author_email = ?
    """, (current_user["name"], current_user["email"]))
    conn.commit()

    rows = conn.execute("""
        SELECT p.id, p.title, p.category, p.meeting_type, p.author_email,
               (SELECT COUNT(*) FROM project_members pm2 WHERE pm2.project_id = p.id) as member_count
        FROM project_members pm
        JOIN projects p ON pm.project_id = p.id
        WHERE pm.member_email = ?
        ORDER BY p.id DESC
    """, (current_user["email"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/projects/{project_id}/members")
def get_project_members(project_id: int):
    conn = get_db()
    rows = conn.execute("""
        SELECT pm.member_name, pm.member_email, u.disc_type, u.major, u.available_time_start, u.available_time_end
        FROM project_members pm
        LEFT JOIN users u ON pm.member_email = u.email
        WHERE pm.project_id = ?
    """, (project_id,)).fetchall()
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
        if project_id in self.rooms and websocket in self.rooms[project_id]:
            self.rooms[project_id].remove(websocket)

    async def broadcast_json(self, project_id: int, data: dict):
        if project_id in self.rooms:
            dead = []
            for connection in self.rooms[project_id]:
                try:
                    await connection.send_text(json.dumps(data, ensure_ascii=False))
                except Exception:
                    dead.append(connection)
            for d in dead:
                self.disconnect(d, project_id)

manager = ConnectionManager()

@app.get("/api/projects/{project_id}/messages")
def get_chat_messages(project_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    is_member = conn.execute(
        "SELECT 1 FROM project_members WHERE project_id = ? AND member_email = ?",
        (project_id, current_user["email"])
    ).fetchone()
    if not is_member:
        conn.close()
        raise HTTPException(status_code=403, detail="해당 팀의 멤버만 채팅을 볼 수 있습니다.")
    rows = conn.execute(
        "SELECT id, project_id, sender_email, sender_name, message, created_at FROM chat_messages WHERE project_id = ? ORDER BY id ASC LIMIT 200",
        (project_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/projects/{project_id}/messages")
async def post_chat_message(project_id: int, payload: ChatMessageCreate, current_user: dict = Depends(get_current_user)):
    text = payload.message.strip()
    if not text:
        raise HTTPException(status_code=400, detail="메시지를 입력해 주세요.")
    conn = get_db()
    is_member = conn.execute(
        "SELECT 1 FROM project_members WHERE project_id = ? AND member_email = ?",
        (project_id, current_user["email"])
    ).fetchone()
    if not is_member:
        conn.close()
        raise HTTPException(status_code=403, detail="해당 팀의 멤버만 메시지를 보낼 수 있습니다.")

    now_str = datetime.datetime.now().strftime("%H:%M")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO chat_messages (project_id, sender_email, sender_name, message, created_at) VALUES (?, ?, ?, ?, ?)",
        (project_id, current_user["email"], current_user["name"], text, now_str)
    )
    msg_id = cur.lastrowid
    conn.commit()
    conn.close()

    msg_obj = {
        "id": msg_id,
        "project_id": project_id,
        "sender_email": current_user["email"],
        "sender_name": current_user["name"],
        "message": text,
        "created_at": now_str
    }
    await manager.broadcast_json(project_id, msg_obj)
    return msg_obj

@app.websocket("/ws/chat/{project_id}/{user_name}")
async def websocket_chat_endpoint(websocket: WebSocket, project_id: int, user_name: str):
    await manager.connect(websocket, project_id)
    try:
        while True:
            raw_text = await websocket.receive_text()
            now_str = datetime.datetime.now().strftime("%H:%M")
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO chat_messages (project_id, sender_email, sender_name, message, created_at) VALUES (?, ?, ?, ?, ?)",
                (project_id, user_name, user_name, raw_text, now_str)
            )
            msg_id = cur.lastrowid
            conn.commit()
            conn.close()
            msg_obj = {
                "id": msg_id,
                "project_id": project_id,
                "sender_email": user_name,
                "sender_name": user_name,
                "message": raw_text,
                "created_at": now_str
            }
            await manager.broadcast_json(project_id, msg_obj)
    except WebSocketDisconnect:
        manager.disconnect(websocket, project_id)
