from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import sqlite3, hashlib, json

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# --- База данных ---
conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    public_key TEXT
)
""")
conn.commit()

# --- REST API ---
@app.post("/register")
async def register(user: dict):
    username = user["username"]
    password = user["password"]
    public_key = user["public_key"]
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
            (username, pw_hash, public_key)
        )
        conn.commit()
        return {"status": "ok"}
    except sqlite3.IntegrityError:
        return {"status": "error", "msg": "Username taken"}

@app.post("/login")
async def login(user: dict):
    username = user["username"]
    password = user["password"]
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute("SELECT * FROM users WHERE username=? AND password_hash=?", (username, pw_hash))
    row = cursor.fetchone()
    if row:
        return {"status": "ok", "public_key": row[3]}
    return {"status": "error", "msg": "Invalid credentials"}

# --- WebSocket чат ---
clients = {}  # username: websocket

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    await websocket.accept()
    clients[username] = websocket
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            target = message.get("to")
            if target in clients:
                await clients[target].send_text(json.dumps(message))
    except WebSocketDisconnect:
        del clients[username]
