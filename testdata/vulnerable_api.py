"""
Intentionally Vulnerable API for APISentry testing.
DO NOT deploy to production. Local testing only.

Vulnerabilities included:
- BOLA (Broken Object Level Authorization): /users/{id}, /accounts/{id}
- Broken Auth: /admin/delete/{id} has no auth check
- Mass Assignment: /users/update accepts any field including 'role'
- Excessive Data Exposure: /users returns password hashes
"""
from fastapi import FastAPI, Header
from typing import Optional
import uvicorn

app = FastAPI(title="Vulnerable Test API", version="1.0")

# Fake database
USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "user", "password_hash": "abc123"},
    2: {"id": 2, "name": "Bob",   "email": "bob@example.com",   "role": "admin","password_hash": "def456"},
    3: {"id": 3, "name": "Carol", "email": "carol@example.com", "role": "user", "password_hash": "ghi789"},
}

VALID_TOKEN = "valid-token-user1"

def is_authenticated(token: Optional[str]) -> bool:
    return token == f"Bearer {VALID_TOKEN}"

# ── BOLA vulnerability ─────────────────────────────────────────────────────────
# Any user can access ANY user's data — no ownership check
@app.get("/users/{user_id}")
def get_user(user_id: int, authorization: Optional[str] = Header(None)):
    if user_id in USERS:
        return USERS[user_id]   # VULNERABLE: returns data for ANY id, incl. password_hash
    return {"error": "not found"}, 404

# ── Broken Auth vulnerability ──────────────────────────────────────────────────
# DELETE /admin/users/{id} — no auth check at all
@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int):
    if user_id in USERS:
        del USERS[user_id]
        return {"deleted": user_id}   # VULNERABLE: no auth required
    return {"error": "not found"}

# ── Properly protected endpoint (should NOT trigger) ──────────────────────────
@app.get("/secure/profile")
def secure_profile(authorization: Optional[str] = Header(None)):
    if not is_authenticated(authorization):
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"id": 1, "name": "Alice"}

# ── Mass Assignment vulnerability ─────────────────────────────────────────────
@app.post("/users/update")
def update_user(user_id: int, data: dict):
    if user_id in USERS:
        USERS[user_id].update(data)   # VULNERABLE: accepts 'role', 'password_hash' etc.
        return USERS[user_id]
    return {"error": "not found"}

# ── Info exposure ──────────────────────────────────────────────────────────────
@app.get("/users")
def list_users():
    return list(USERS.values())   # VULNERABLE: exposes all users incl. password hashes

if __name__ == "__main__":
    print("\n🎯 Vulnerable Test API running at http://localhost:8080")
    print("   This is intentionally vulnerable — for APISentry testing only\n")
    uvicorn.run(app, host="127.0.0.1", port=8080, log_level="warning")
