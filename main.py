import json
import sqlite3
import hashlib
import datetime
import os
from typing import Optional, List, Dict
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import jwt

app = FastAPI(title="TeamSync API", description="DISC 기반 공모전/팀플 매칭 및 실시간 팀 채팅 백엔드")

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

def ensure_column(cur, table: str, column: str, col_type: str):
    cur.execute(f"PRAGMA table_info({table})")
    cols = [row[1] for row in cur.fetchall()]
    if column not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")

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
    ensure_column(cur, "users", "available_time_start", "TEXT DEFAULT '09:00'")
    ensure_column(cur, "users", "available_time_end", "TEXT DEFAULT '18:00'")

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
    ensure_column(cur, "projects", "image_url", "TEXT")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS project_applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        applicant_email TEXT NOT NULL,
        applicant_name TEXT NOT NULL,
        message TEXT DEFAULT '',
        status TEXT DEFAULT 'pending',
        created_at TEXT
    )
    """)
    ensure_column(cur, "project_applications", "message", "TEXT DEFAULT ''")
    ensure_column(cur, "project_applications", "created_at", "TEXT")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS project_members (
        project_id INTEGER NOT NULL,
        member_email TEXT NOT NULL,
        member_name TEXT NOT NULL,
        role TEXT DEFAULT '팀원',
        PRIMARY KEY (project_id, member_email)
    )
    """)
    ensure_column(cur, "project_members", "role", "TEXT DEFAULT '팀원'")

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

class ApplyPayload(BaseModel):
    message: Optional[str] = "열심히 참여하겠습니다!"

class ChatCreate(BaseModel):
    message: str

class KickPayload(BaseModel):
    member_email: str

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
            raise HTTPException(status_code=401, detail="존재하지 않는 사용자입니다. 다시 로그인해 주세요.")
        return dict(user)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="세션이 만료되었습니다. 다시 로그인해 주세요.")

@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h3>index.html 파일을 찾을 수 없습니다.</h3>"

# ----------------------------------------------------
# 회원 API
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
    return {"message": f"{data.name}님, 회원가입이 완료되었습니다!"}

@app.post("/api/auth/login")
def login(data: UserLogin):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (data.email,)).fetchone()
    conn.close()
    if not user or user["password_hash"] != hash_pw(data.password):
        raise HTTPException(status_code=401, detail="이메일 또는 비밀번호가 올바르지 않습니다.")
    token = create_token(data.email)
    return {
        "access_token": token,
        "token_type": "bearer",
        "name": user["name"],
        "email": user["email"],
        "disc_type": user["disc_type"]
    }

@app.get("/api/users/me")
def read_my_profile(current_user: dict = Depends(get_current_user)):
    current_user.pop("password_hash", None)
    current_user["disc_scores"] = json.loads(current_user.get("disc_scores") or '{"D":0,"I":0,"S":0,"C":0}')
    current_user["preferred_roles"] = json.loads(current_user.get("preferred_roles") or "[]")
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
# DISC 40문항 진단 API
# ----------------------------------------------------
DEFAULT_DISC_QUESTIONS = [
    {"id": "1", "question": "나는 팀 프로젝트에서 목표를 빠르게 설정하고 주도적으로 이끄는 편이다.", "style": "D", "keyed": 1},
    {"id": "2", "question": "나는 처음 만난 팀원들과도 쉽게 대화를 시작하고 분위기를 밝게 만든다.", "style": "I", "keyed": 1},
    {"id": "3", "question": "나는 팀원들의 의견을 경청하며 갈등 없이 안정적으로 협력하는 것이 중요하다.", "style": "S", "keyed": 1},
    {"id": "4", "question": "나는 자료를 조사할 때 출처와 데이터의 정확성을 꼼꼼하게 검증한다.", "style": "C", "keyed": 1},
    {"id": "5", "question": "어려운 과제가 주어지면 망설이기보다 즉시 해결책을 찾아 실행에 옮긴다.", "style": "D", "keyed": 1},
    {"id": "6", "question": "회의에서 새로운 아이디어를 제안하고 사람들을 설득하는 일을 즐긴다.", "style": "I", "keyed": 1},
    {"id": "7", "question": "갑작스러운 계획 변경보다는 정해진 일정을 꾸준히 지키는 것이 편하다.", "style": "S", "keyed": 1},
    {"id": "8", "question": "업무를 시작하기 전에 세부적인 계획과 체크리스트를 먼저 작성한다.", "style": "C", "keyed": 1},
    {"id": "9", "question": "경쟁적인 상황에서 더 큰 동기를 얻고 우승이나 최고 성과를 목표로 한다.", "style": "D", "keyed": 1},
    {"id": "10", "question": "발표나 프레젠테이션을 맡아 청중의 호응을 이끌어내는 것에 자신이 있다.", "style": "I", "keyed": 1},
    {"id": "11", "question": "팀원이 어려움을 겪고 있으면 내 일을 멈추고서라도 도와주려고 한다.", "style": "S", "keyed": 1},
    {"id": "12", "question": "결과물의 완성도를 높이기 위해 사소한 오타나 디자인 정렬까지 신경 쓴다.", "style": "C", "keyed": 1},
    {"id": "13", "question": "의사결정이 지연되면 답답함을 느끼며 빠르게 결론을 내리고자 한다.", "style": "D", "keyed": 1},
    {"id": "14", "question": "다양한 전공이나 배경을 가진 사람들과 네트워킹하는 것이 즐겁다.", "style": "I", "keyed": 1},
    {"id": "15", "question": "내가 맡은 역할은 끝까지 책임지고 묵묵히 완수해내는 편이다.", "style": "S", "keyed": 1},
    {"id": "16", "question": "감이나 직관보다는 객관적인 근거와 논리적인 분석을 신뢰한다.", "style": "C", "keyed": 1},
    {"id": "17", "question": "문제 상황에서 핵심을 짚어내고 직설적으로 피드백을 주고받는다.", "style": "D", "keyed": 1},
    {"id": "18", "question": "칭찬과 긍정적인 피드백을 주고받을 때 팀의 시너지가 난다고 믿는다.", "style": "I", "keyed": 1},
    {"id": "19", "question": "팀 내에서 중재자 역할을 맡아 서로 다른 의견을 조율하는 편이다.", "style": "S", "keyed": 1},
    {"id": "20", "question": "규칙과 가이드라인, 평가 기준을 철저히 분석하여 과제에 반영한다.", "style": "C", "keyed": 1},
    {"id": "21", "question": "권한과 책임이 주어지는 팀장이나 리더 역할을 맡는 것이 부담스럽지 않다.", "style": "D", "keyed": 1},
    {"id": "22", "question": "딱딱한 회의보다는 자유롭고 활발한 브레인스토밍 환경을 선호한다.", "style": "I", "keyed": 1},
    {"id": "23", "question": "동료들이 나에게 고민이나 어려움을 편하게 털어놓는 편이다.", "style": "S", "keyed": 1},
    {"id": "24", "question": "복잡한 문제를 구조화하고 표나 그래프로 정리하는 작업에 능숙하다.", "style": "C", "keyed": 1},
    {"id": "25", "question": "장애물이 생기면 포기하기보다 돌파구를 찾아내어 결과를 만들어낸다.", "style": "D", "keyed": 1},
    {"id": "26", "question": "열정적이고 에너지 넘치는 태도로 주변 사람들의 사기를 북돋운다.", "style": "I", "keyed": 1},
    {"id": "27", "question": "한 번에 여러 일을 벌이기보다 한 가지 일에 차분히 집중하는 것을 선호한다.", "style": "S", "keyed": 1},
    {"id": "28", "question": "예상치 못한 리스크나 오류 가능성을 미리 점검하고 대비책을 세운다.", "style": "C", "keyed": 1},
    {"id": "29", "question": "효율성을 중시하며 불필요한 절차를 줄이고 핵심에 집중한다.", "style": "D", "keyed": 1},
    {"id": "30", "question": "아이디어를 시각적으로 표현하거나 스토리텔링으로 풀어내는 것을 좋아한다.", "style": "I", "keyed": 1},
    {"id": "31", "question": "팀의 화합과 평화로운 분위기를 유지하는 것이 성과만큼 중요하다.", "style": "S", "keyed": 1},
    {"id": "32", "question": "내 작업물에 대해 높은 기준을 가지고 있으며 스스로 검수를 반복한다.", "style": "C", "keyed": 1},
    {"id": "33", "question": "새로운 도전이나 리스크가 있더라도 큰 보상이 기대되면 과감히 시도한다.", "style": "D", "keyed": 1},
    {"id": "34", "question": "유머 감각이 있으며 지루한 팀플 시간도 즐겁게 만드는 편이다.", "style": "I", "keyed": 1},
    {"id": "35", "question": "약속 시간과 마감 기한을 어기지 않고 성실하게 지킨다.", "style": "S", "keyed": 1},
    {"id": "36", "question": "질문을 할 때 추상적인 표현보다 구체적이고 명확한 답변을 원한다.", "style": "C", "keyed": 1},
    {"id": "37", "question": "팀의 방향성이 흔들릴 때 결단력 있게 방향을 잡아준다.", "style": "D", "keyed": 1},
    {"id": "38", "question": "외부 기관 컨택이나 인터뷰, 설문 홍보 등 대외적인 활동에 적극적이다.", "style": "I", "keyed": 1},
    {"id": "39", "question": "앞에 나서기보다 뒤에서 팀원들을 든든하게 서포트하는 역할에 보람을 느낀다.", "style": "S", "keyed": 1},
    {"id": "40", "question": "최종 제출 전 요구사항이 모두 충족되었는지 체계적으로 최종 점검한다.", "style": "C", "keyed": 1}
]

def load_disc_items():
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
                    it["id"] = str(it.get("id", idx + 1))
                return selected
        except Exception:
            pass
    return DEFAULT_DISC_QUESTIONS

@app.get("/api/disc/questions")
def get_disc_questions():
    questions = load_disc_items()
    return {"total": len(questions), "questions": questions}

@app.post("/api/disc/submit")
def submit_disc(payload: DiscSubmit, current_user: dict = Depends(get_current_user)):
    items = load_disc_items()
    items_map = {str(item["id"]): item for item in items}

    scores = {"D": 0, "I": 0, "S": 0, "C": 0}
    for q_id, raw_val in payload.answers.items():
        val = int(raw_val)
        q_str = str(q_id)
        if q_str in items_map:
            item = items_map[q_str]
            score = val if item.get("keyed", 1) == 1 else (6 - val)
            style = item.get("style", "C")
            if style in scores:
                scores[style] += score
        else:
            idx = int(q_id) % 4 if str(q_id).isdigit() else 0
            scores[["D", "I", "S", "C"][idx]] += val

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
# 공모전 / 팀원 모집 / 지원 / 수락 / 강퇴 API
# ----------------------------------------------------
@app.get("/api/projects")
def get_projects():
    conn = get_db()
    rows = conn.execute("""
        SELECT p.*, u.name as author_name, u.disc_type as author_disc
        FROM projects p
        LEFT JOIN users u ON p.author_email = u.email
        ORDER BY p.id DESC
    """).fetchall()

    projects = []
    for r in rows:
        p = dict(r)
        p["needed_roles"] = json.loads(p["needed_roles"] or "[]")
        p["needed_disc"] = json.loads(p["needed_disc"] or "[]")
        mem_cnt = conn.execute("SELECT COUNT(*) FROM project_members WHERE project_id = ?", (p["id"],)).fetchone()[0]
        pend_cnt = conn.execute("SELECT COUNT(*) FROM project_applications WHERE project_id = ? AND status = 'pending'", (p["id"],)).fetchone()[0]
        p["member_count"] = mem_cnt
        p["pending_count"] = pend_cnt
        projects.append(p)
    conn.close()
    return projects

@app.post("/api/projects")
def create_project(proj: ProjectCreate, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    cur.execute(
        """INSERT INTO projects 
           (author_email, category, title, description, meeting_type, needed_roles, needed_disc, commitment_level, available_time, image_url, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            current_user["email"], proj.category, proj.title, proj.description,
            proj.meeting_type,
            json.dumps(proj.needed_roles, ensure_ascii=False),
            json.dumps(proj.needed_disc, ensure_ascii=False),
            proj.commitment_level, proj.available_time, proj.image_url,
            now_str
        )
    )
    project_id = cur.lastrowid
    cur.execute(
        "INSERT OR IGNORE INTO project_members (project_id, member_email, member_name, role) VALUES (?, ?, ?, '팀장')",
        (project_id, current_user["email"], current_user["name"])
    )
    cur.execute(
        "INSERT INTO chat_messages (project_id, sender_email, sender_name, message, created_at) VALUES (?, 'system', '시스템', ?, ?)",
        (project_id, f"🎉 '{proj.title}' 팀 채팅방이 개설되었습니다. 수락된 팀원들과 자유롭게 대화해보세요!", now_str)
    )
    conn.commit()
    conn.close()
    return {"message": "모집글이 등록되었으며 팀 채팅방이 생성되었습니다!", "project_id": project_id}

@app.delete("/api/projects/{project_id}")
def delete_project(project_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj or proj["author_email"] != current_user["email"]:
        conn.close()
        raise HTTPException(status_code=403, detail="삭제 권한이 없습니다.")
    conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    conn.execute("DELETE FROM project_applications WHERE project_id = ?", (project_id,))
    conn.execute("DELETE FROM project_members WHERE project_id = ?", (project_id,))
    conn.execute("DELETE FROM chat_messages WHERE project_id = ?", (project_id,))
    conn.commit()
    conn.close()
    return {"message": "모집글이 삭제되었습니다."}

@app.post("/api/projects/{project_id}/apply")
def apply_project(project_id: int, payload: Optional[ApplyPayload] = None, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404, detail="공모전 글을 찾을 수 없습니다.")
    if proj["author_email"] == current_user["email"]:
        conn.close()
        raise HTTPException(status_code=400, detail="본인이 개설한 모집글에는 이미 팀장으로 참여 중입니다.")

    existing = conn.execute(
        "SELECT * FROM project_applications WHERE project_id = ? AND applicant_email = ?",
        (project_id, current_user["email"])
    ).fetchone()
    if existing:
        conn.close()
        status_kor = {
            "pending": "심사 대기 중",
            "accepted": "이미 수락됨",
            "rejected": "거절됨",
            "kicked": "강퇴됨"
        }.get(existing["status"], existing["status"])
        raise HTTPException(status_code=400, detail=f"이미 지원한 이력이 있는 공모전입니다. (현재 상태: {status_kor})")

    msg = payload.message if payload and payload.message else "열심히 참여하겠습니다!"
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    conn.execute(
        "INSERT INTO project_applications (project_id, applicant_email, applicant_name, message, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
        (project_id, current_user["email"], current_user["name"], msg, now_str)
    )
    conn.commit()
    conn.close()
    return {"message": "공모전 지원이 완료되었습니다! 작성자가 수락하면 팀 채팅방에 자동 초대됩니다."}

@app.get("/api/my-applications")
def get_my_applications(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute("""
        SELECT pa.*, p.title as project_title, p.category
        FROM project_applications pa
        JOIN projects p ON pa.project_id = p.id
        WHERE pa.applicant_email = ?
        ORDER BY pa.id DESC
    """, (current_user["email"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/projects/{project_id}/applications")
def get_project_applications(project_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj or proj["author_email"] != current_user["email"]:
        conn.close()
        raise HTTPException(status_code=403, detail="작성자만 조회할 수 있습니다.")
    rows = conn.execute("""
        SELECT pa.*, u.major, u.disc_type, u.available_time_start, u.available_time_end, u.preferred_roles
        FROM project_applications pa
        LEFT JOIN users u ON pa.applicant_email = u.email
        WHERE pa.project_id = ? AND pa.status = 'pending'
        ORDER BY pa.id DESC
    """, (project_id,)).fetchall()
    conn.close()
    res = []
    for r in rows:
        d = dict(r)
        d["preferred_roles"] = json.loads(d.get("preferred_roles") or "[]")
        res.append(d)
    return res

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

    now_str = datetime.datetime.now().strftime("%H:%M")
    if action == "accept":
        conn.execute("UPDATE project_applications SET status = 'accepted' WHERE id = ?", (app_id,))
        conn.execute(
            "INSERT OR IGNORE INTO project_members (project_id, member_email, member_name, role) VALUES (?, ?, ?, '팀원')",
            (app_row["project_id"], app_row["applicant_email"], app_row["applicant_name"])
        )
        conn.execute(
            "INSERT INTO chat_messages (project_id, sender_email, sender_name, message, created_at) VALUES (?, 'system', '시스템', ?, ?)",
            (app_row["project_id"], f"👏 {app_row['applicant_name']}님이 새로운 팀원으로 합류했습니다!", now_str)
        )
        conn.commit()
        conn.close()
        return {"message": f"{app_row['applicant_name']}님의 지원을 수락했습니다! 팀 단체 채팅방에 초대되었습니다."}
    elif action == "reject":
        conn.execute("UPDATE project_applications SET status = 'rejected' WHERE id = ?", (app_id,))
        conn.commit()
        conn.close()
        return {"message": f"{app_row['applicant_name']}님의 지원을 거절했습니다."}
    else:
        conn.close()
        raise HTTPException(status_code=400, detail="올바르지 않은 요청입니다.")

@app.post("/api/projects/{project_id}/kick")
def kick_team_member(project_id: int, payload: KickPayload, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404, detail="프로젝트를 찾을 수 없습니다.")
    if proj["author_email"] != current_user["email"]:
        conn.close()
        raise HTTPException(status_code=403, detail="팀장만 팀원을 강퇴할 수 있습니다.")
    if payload.member_email == current_user["email"]:
        conn.close()
        raise HTTPException(status_code=400, detail="팀장 본인은 강퇴할 수 없습니다.")

    member = conn.execute(
        "SELECT * FROM project_members WHERE project_id = ? AND member_email = ?",
        (project_id, payload.member_email)
    ).fetchone()
    if not member:
        conn.close()
        raise HTTPException(status_code=404, detail="해당 팀원을 찾을 수 없습니다.")

    kicked_name = member["member_name"]
    conn.execute(
        "DELETE FROM project_members WHERE project_id = ? AND member_email = ?",
        (project_id, payload.member_email)
    )
    conn.execute(
        "UPDATE project_applications SET status = 'kicked' WHERE project_id = ? AND applicant_email = ?",
        (project_id, payload.member_email)
    )
    now_str = datetime.datetime.now().strftime("%H:%M")
    conn.execute(
        "INSERT INTO chat_messages (project_id, sender_email, sender_name, message, created_at) VALUES (?, 'system', '시스템', ?, ?)",
        (project_id, f"🚫 {kicked_name}님이 팀장에 의해 팀에서 강퇴되었습니다.", now_str)
    )
    conn.commit()
    conn.close()
    return {"message": f"{kicked_name}님을 팀에서 강퇴했습니다."}

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
                  available_time_start, available_time_end, portfolio_url
           FROM users WHERE is_seeking = 1 AND email != ?""",
        (proj["author_email"],)
    ).fetchall()
    conn.close()

    recommendations = []
    for c in candidates:
        c_dict = dict(c)
        c_roles = json.loads(c_dict["preferred_roles"] or "[]")
        match_score = 20
        reasons = []
        if c_dict["disc_type"] and c_dict["disc_type"] in needed_disc:
            match_score += 50
            reasons.append(f"선호 성향({c_dict['disc_type']}형) 일치")
        matched_roles = set(needed_roles) & set(c_roles)
        if matched_roles:
            match_score += 30 * len(matched_roles)
            reasons.append(f"희망 역할({', '.join(matched_roles)}) 일치")
        if not reasons:
            reasons.append("현재 팀 구직 활성 사용자")
        c_dict["preferred_roles"] = c_roles
        c_dict["disc_scores"] = json.loads(c_dict["disc_scores"] or "{}")
        c_dict["match_score"] = min(match_score, 100)
        c_dict["match_reasons"] = reasons
        recommendations.append(c_dict)

    recommendations.sort(key=lambda x: x["match_score"], reverse=True)
    return {"project_title": proj["title"], "recommended_users": recommendations}

# ----------------------------------------------------
# 팀 단체 채팅 API (DB 영구 저장 + 실시간 폴링)
# ----------------------------------------------------
@app.get("/api/my-teams")
def get_my_teams(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute("""
        SELECT p.id, p.title, p.category, p.meeting_type, p.author_email, pm.role
        FROM project_members pm
        JOIN projects p ON pm.project_id = p.id
        WHERE pm.member_email = ?
        ORDER BY p.id DESC
    """, (current_user["email"],)).fetchall()
    teams = []
    for r in rows:
        t = dict(r)
        cnt = conn.execute("SELECT COUNT(*) FROM project_members WHERE project_id = ?", (t["id"],)).fetchone()[0]
        last_msg = conn.execute("SELECT message, created_at FROM chat_messages WHERE project_id = ? ORDER BY id DESC LIMIT 1", (t["id"],)).fetchone()
        t["member_count"] = cnt
        t["last_message"] = last_msg["message"] if last_msg else "대화를 시작해보세요!"
        teams.append(t)
    conn.close()
    return teams

@app.get("/api/projects/{project_id}/members")
def get_project_members(project_id: int):
    conn = get_db()
    rows = conn.execute("""
        SELECT pm.member_name, pm.member_email, pm.role, u.disc_type, u.major, u.available_time_start, u.available_time_end
        FROM project_members pm
        LEFT JOIN users u ON pm.member_email = u.email
        WHERE pm.project_id = ?
        ORDER BY CASE WHEN pm.role = '팀장' THEN 0 ELSE 1 END, pm.member_name ASC
    """, (project_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/projects/{project_id}/messages")
def get_chat_messages(project_id: int, after_id: int = 0, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    is_mem = conn.execute(
        "SELECT 1 FROM project_members WHERE project_id = ? AND member_email = ?",
        (project_id, current_user["email"])
    ).fetchone()
    if not is_mem:
        conn.close()
        raise HTTPException(status_code=403, detail="해당 팀의 멤버만 채팅을 볼 수 있습니다.")

    rows = conn.execute(
        "SELECT id, project_id, sender_email, sender_name, message, created_at FROM chat_messages WHERE project_id = ? AND id > ? ORDER BY id ASC",
        (project_id, after_id)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/projects/{project_id}/messages")
def post_chat_message(project_id: int, payload: ChatCreate, current_user: dict = Depends(get_current_user)):
    msg_text = payload.message.strip()
    if not msg_text:
        raise HTTPException(status_code=400, detail="메시지를 입력해주세요.")

    conn = get_db()
    is_mem = conn.execute(
        "SELECT 1 FROM project_members WHERE project_id = ? AND member_email = ?",
        (project_id, current_user["email"])
    ).fetchone()
    if not is_mem:
        conn.close()
        raise HTTPException(status_code=403, detail="해당 팀의 멤버만 메시지를 보낼 수 있습니다.")

    now_str = datetime.datetime.now().strftime("%H:%M")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO chat_messages (project_id, sender_email, sender_name, message, created_at) VALUES (?, ?, ?, ?, ?)",
        (project_id, current_user["email"], current_user["name"], msg_text, now_str)
    )
    msg_id = cur.lastrowid
    conn.commit()
    conn.close()

    return {
        "id": msg_id,
        "project_id": project_id,
        "sender_email": current_user["email"],
        "sender_name": current_user["name"],
        "message": msg_text,
        "created_at": now_str
    }
