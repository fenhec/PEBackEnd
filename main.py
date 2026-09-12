import os
import time
import logging
import jwt
import bcrypt
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Request, status, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse, JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

# 1. LOGGING & CONFIG
load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PointExchange")

ALGORITHM = "HS256"
MONGO_URI = os.getenv("MONGO_URI", "mongodb://192.168.1.118:27018/")
API_HOST = os.getenv("API_HOST", "0.0.0.0")
DB_NAME = os.getenv("MONGO_DB", "pointexchange")
API_PORT = int(os.getenv("API_PORT", "8088"))
JWT_SECRET="point_exchange_super_secure_and_very_long_secret_key_2026_!@#"


# 2. REAL-TIME CONNECTION MANAGER
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, user_id: str, websocket: WebSocket, db_ref):
        await websocket.accept()
        self.active_connections[user_id] = websocket
        user = await db_ref.users.find_one({"id": user_id}, {"name": 1})
        username = user.get("name") if user else "Unknown"
        logger.info(f"WebSocket Connected: {username} ({user_id})")

    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
            logger.info(f"WebSocket Disconnected: User {user_id}")

    async def notify_user(self, user_id: str, message: str):
        if user_id in self.active_connections:
            try:
                await self.active_connections[user_id].send_text(message)
            except Exception:
                self.disconnect(user_id)

    async def notify_group(self, group_id: str, message: str, db_ref):
        users = await db_ref.users.find({"groupId": group_id}, {"id": 1}).to_list(length=1000)
        for u in users:
            await self.notify_user(u["id"], message)

manager = ConnectionManager()
login_attempts: Dict[str, List[float]] = {}
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 10

# 3. SECURITY UTILS
def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password[:72].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try: return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception: return False

def create_access_token(data: dict):
    to_encode = data.copy()
    now_utc = datetime.utcnow()
    expire = now_utc + timedelta(days=30)
    to_encode.update({"iat": now_utc, "exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

def decode_token(token: str):
    try: return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except Exception: return None

async def get_current_user_from_request(request: Request):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "): return None
    token_data = decode_token(auth.split(" ", 1)[1])
    if not token_data or not token_data.get("sub"): return None
    user = await db.users.find_one({"id": token_data["sub"]})
    if not user: return None
    if int(token_data.get("ver", 0)) != int(user.get("authVersion", 0)): return None
    return user

def is_admin(user: Optional[Dict]) -> bool:
    return bool(user and user.get("role") == "ADMIN")

def same_group(user: Optional[Dict], group_id: Optional[str]) -> bool:
    return bool(user and group_id and user.get("groupId") == group_id)

# 4. DATABASE & LIFESPAN
client = AsyncIOMotorClient(MONGO_URI)
db = client[DB_NAME]

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Connecting to MongoDB at {MONGO_URI}...")
    try:
        await client.admin.command('ping')
        for col in ["users", "groups", "achievements", "rewards", "requests", "activity", "tags"]:
            if col not in await db.list_collection_names(): await db.create_collection(col)
        logger.info("Database Ready.")
    except Exception as e: logger.error(f"STARTUP ERROR: {e}")
    yield
    client.close()

app = FastAPI(title="PointExchange Final Backend", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    return response

# 5. WEBSOCKET ENDPOINT
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    await manager.connect(user_id, websocket, db)
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(user_id)

# 6. HELPERS
async def get_populated_user(user_doc: Dict, limit: int = 20, offset: int = 0):
    user_id = user_doc["id"]
    activity = await db.activity.find({"userId": user_id}).sort("timestamp", -1).skip(offset).limit(limit).to_list(length=limit)
    earned, redeemed = [], []
    for act in activity:
        event = {"title": act["title"], "timestamp": int(act["timestamp"]), "points": abs(int(act.get("points", 0))), "tagId": act.get("tagId")}
        if act["type"] == 'ACHIEVEMENT': earned.append(event)
        else: redeemed.append(event)
    user_doc["earnedAchievements"] = earned
    user_doc["redeemedRewards"] = redeemed
    user_doc["points"] = int(user_doc.get("points", 0))
    if "_id" in user_doc: del user_doc["_id"]
    if "password" in user_doc: del user_doc["password"]
    return user_doc

# 7. GET ACTIONS
@app.get("/exec")
async def handle_get(request: Request, action: str, email: Optional[str] = None, password: Optional[str] = None,
                     groupId: Optional[str] = None, userId: Optional[str] = None, includeUsers: str = "true"):
    try:
        params = request.query_params
        last_sync = max(0, int(params.get("lastSync", 0)))
        act_limit = max(1, min(int(params.get("activityLimit", 20)), 100))
        act_offset = max(0, int(params.get("activityOffset", 0)))

        if action == "login":
            if not email or not password: return JSONResponse(content="Error")
            client_ip = request.client.host if request.client else "unknown"
            cutoff = time.time() - LOGIN_WINDOW_SECONDS
            attempts = [t for t in login_attempts.get(client_ip, []) if t > cutoff]
            if len(attempts) >= LOGIN_MAX_ATTEMPTS: return PlainTextResponse(content="Too Many Requests", status_code=429)
            user = await db.users.find_one({"email": email.lower().strip()})
            if not user or not verify_password(password, user["password"]):
                attempts.append(time.time()); login_attempts[client_ip] = attempts
                return JSONResponse(content="Error")
            login_attempts.pop(client_ip, None)
            token = create_access_token({"sub": user["id"], "email": user["email"], "ver": int(user.get("authVersion", 0))})
            logger.info(f"USER LOGIN: {user.get('name')} ({user.get('email')})")
            populated = await get_populated_user(user, limit=act_limit, offset=act_offset)
            populated["token"] = token
            group = await db.groups.find_one({"id": user["groupId"]})
            if group and "_id" in group: del group["_id"]
            return JSONResponse(content={"user": populated, "group": group or {"id": user["groupId"], "name": "Default Group", "ownerAdminId": user["id"]}})

        current_user = await get_current_user_from_request(request)
        if action == "getEmails": # Special case: Allowed if admin
            if not current_user: return PlainTextResponse(content="") # Safe fail for older app versions
            if not is_admin(current_user): return PlainTextResponse(content="Forbidden", status_code=403)
            users = await db.users.find({"groupId": current_user["groupId"]}, {"email": 1}).to_list(length=5000)
            return PlainTextResponse(content=",".join([u["email"] for u in users]))

        if not current_user: return PlainTextResponse(content="Unauthorized", status_code=401)

        if action == "getData":
            if groupId == "validate":
                if not userId: return PlainTextResponse(content="Unauthorized", status_code=401)
                user = await db.users.find_one({"email": userId.lower().strip()})
                if not user or user.get("groupId") != current_user.get("groupId"): return PlainTextResponse(content="Unauthorized", status_code=401)
                group = await db.groups.find_one({"id": user["groupId"]})
                if group and "_id" in group: del group["_id"]
                return JSONResponse(content={"user": await get_populated_user(user, limit=act_limit, offset=act_offset), "group": group})

            if not same_group(current_user, groupId): return PlainTextResponse(content="Forbidden", status_code=403)
            sync_query = {"groupId": groupId}
            if last_sync > 0: sync_query["updatedAt"] = {"$gt": last_sync}
            all_users = await db.users.find({"groupId": groupId}).to_list(length=1000)
            my_rank = 0
            if userId:
                sorted_users = sorted(all_users, key=lambda x: x.get("points", 0), reverse=True)
                for i, u in enumerate(sorted_users):
                    if u["id"] == userId: my_rank = i + 1; break
            users_docs = await db.users.find(sync_query).to_list(length=1000) if includeUsers == "true" else []
            users_list = [await get_populated_user(u, limit=act_limit, offset=act_offset) for u in users_docs]
            achievements = await db.achievements.find(sync_query).to_list(1000)
            rewards = await db.rewards.find(sync_query).to_list(1000)
            requests = await db.requests.find(sync_query).to_list(1000)
            tags = await db.tags.find(sync_query).to_list(1000)
            for coll in [achievements, rewards, requests, tags]:
                for item in coll:
                    if "_id" in item: del item["_id"]
            return JSONResponse(content={"users": users_list, "achievements": achievements, "rewards": rewards, "requests": requests, "tags": tags, "rank": my_rank, "serverTime": int(time.time() * 1000)})

        if action == "getActivity":
            target_user = await db.users.find_one({"id": userId})
            if not target_user or target_user.get("groupId") != current_user.get("groupId"): return PlainTextResponse(content="Forbidden", status_code=403)
            activity_docs = await db.activity.find({"userId": userId}).sort("timestamp", -1).skip(act_offset).limit(act_limit).to_list(length=act_limit)
            return JSONResponse(content=[{"title": a["title"], "timestamp": int(a["timestamp"]), "points": abs(int(a.get("points", 0))), "tagId": a.get("tagId"), "type": a["type"]} for a in activity_docs])
    except Exception:
        logger.exception("GET /exec failed")
        return PlainTextResponse(content="Internal Server Error", status_code=500)

# 8. POST ACTIONS
@app.post("/exec")
async def handle_post(request: Request):
    try:
        data = await request.json()
        action = data.get("action")
        now = int(time.time() * 1000)
        current_user = None
        if action != "registerAdmin":
            current_user = await get_current_user_from_request(request)
            if not current_user: return PlainTextResponse(content="Unauthorized", status_code=401)

        admin_actions = {"addUser", "editUser", "addTag", "editTag", "addAchievement", "editAchievement", "awardAchievement", "addReward", "editReward", "authorizeRequest", "editGroup", "updatePoints", "delete"}
        if action in admin_actions and not is_admin(current_user): return PlainTextResponse(content="Forbidden", status_code=403)

        # --- HANDLERS ---
        if action == "registerAdmin":
            h_pass = get_password_hash(data["password"])
            await db.groups.insert_one({"id": data["groupId"], "name": data["groupName"], "ownerAdminId": data["adminId"], "updatedAt": now})
            await db.users.insert_one({"id": data["adminId"], "groupId": data["groupId"], "name": data["name"], "email": data["email"].lower().strip(), "password": h_pass, "role": "ADMIN", "points": 0, "authVersion": 0, "updatedAt": now})
            logger.info(f"AUDIT: New Group Registered - {data['groupName']} by {data['name']}")

        elif action == "addUser":
            if not same_group(current_user, data.get("groupId")): return PlainTextResponse(content="Forbidden", status_code=403)
            if await db.users.find_one({"email": data.get("email", "").lower().strip()}): return PlainTextResponse(content="Error: Email exists")
            await db.users.insert_one({"id": data["id"], "groupId": data["groupId"], "name": data["name"], "email": data["email"].lower().strip(), "password": get_password_hash(data["password"]), "role": data["role"], "points": 0, "authVersion": 0, "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)
            logger.info(f"AUDIT: Admin {current_user['name']} added user {data['name']}")

        elif action == "editUser":
            target = await db.users.find_one({"id": data["id"]})
            if not target or target.get("groupId") != current_user.get("groupId"): return PlainTextResponse(content="Forbidden", status_code=403)
            await db.users.update_one({"id": data["id"]}, {"$set": {"name": data["name"], "email": data["email"].lower().strip(), "role": data["role"], "updatedAt": now}})
            await manager.notify_user(data["id"], "REFRESH")
            logger.info(f"AUDIT: Admin {current_user['name']} edited user {target['name']}")

        elif action == "addTag":
            await db.tags.insert_one({"id": data["id"], "groupId": data["groupId"], "name": data["name"], "colorHex": data["colorHex"], "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)
            logger.info(f"AUDIT: Admin {current_user['name']} added tag '{data['name']}'")

        elif action == "editTag":
            tag = await db.tags.find_one({"id": data["id"]})
            if not tag or tag.get("groupId") != current_user.get("groupId"): return PlainTextResponse(content="Forbidden", status_code=403)
            await db.tags.update_one({"id": data["id"]}, {"$set": {"name": data["name"], "colorHex": data["colorHex"], "updatedAt": now}})
            await manager.notify_group(tag["groupId"], "REFRESH", db)
            logger.info(f"AUDIT: Admin {current_user['name']} edited tag '{tag['name']}'")

        elif action == "addAchievement":
            await db.achievements.insert_one({"id": data["id"], "groupId": data["groupId"], "title": data["title"], "description": data["description"], "points": int(data["points"]), "tagId": data.get("tagId"), "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)
            logger.info(f"AUDIT: Admin {current_user['name']} added achievement '{data['title']}'")

        elif action == "editAchievement":
            ach = await db.achievements.find_one({"id": data["id"]})
            if not ach or ach.get("groupId") != current_user.get("groupId"): return PlainTextResponse(content="Forbidden", status_code=403)
            await db.achievements.update_one({"id": data["id"]}, {"$set": {"title": data["title"], "description": data["description"], "points": int(data["points"]), "tagId": data.get("tagId"), "updatedAt": now}})
            await manager.notify_group(ach["groupId"], "REFRESH", db)
            logger.info(f"AUDIT: Admin {current_user['name']} edited achievement '{ach['title']}'")

        elif action == "awardAchievement":
            ach = await db.achievements.find_one({"id": data["achievementId"]})
            target = await db.users.find_one({"id": data["userId"]})
            if not ach or not target or ach.get("groupId") != current_user.get("groupId"): return PlainTextResponse(content="Forbidden", status_code=403)
            await db.activity.insert_one({"userId": data["userId"], "groupId": ach["groupId"], "title": ach["title"], "type": "ACHIEVEMENT", "timestamp": now, "points": abs(int(ach["points"])), "tagId": ach.get("tagId"), "performedById": current_user.get("id"), "performedBy": current_user.get("name")})
            await db.users.update_one({"id": data["userId"]}, {"$inc": {"points": int(ach["points"])}, "$set": {"updatedAt": now}})
            await manager.notify_user(data["userId"], "REFRESH")
            logger.info(f"AUDIT: Admin {current_user['name']} awarded '{ach['title']}' to {target['name']}")

        elif action == "addReward":
            await db.rewards.insert_one({"id": data["id"], "groupId": data["groupId"], "title": data["title"], "description": data["description"], "pointCost": int(data["pointCost"]), "cooldownDays": int(data.get("cooldownDays", 0)), "tagId": data.get("tagId"), "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)
            logger.info(f"AUDIT: Admin {current_user['name']} added reward '{data['title']}'")

        elif action == "editReward":
            rew = await db.rewards.find_one({"id": data["id"]})
            if not rew or rew.get("groupId") != current_user.get("groupId"): return PlainTextResponse(content="Forbidden", status_code=403)
            await db.rewards.update_one({"id": data["id"]}, {"$set": {"title": data["title"], "description": data["description"], "pointCost": int(data["pointCost"]), "cooldownDays": int(data.get("cooldownDays", 0)), "tagId": data.get("tagId"), "updatedAt": now}})
            await manager.notify_group(rew["groupId"], "REFRESH", db)
            logger.info(f"AUDIT: Admin {current_user['name']} edited reward '{rew['title']}'")

        elif action == "addRequest":
            if data.get("userId") != current_user.get("id"): return PlainTextResponse(content="Forbidden", status_code=403)
            reward = await db.rewards.find_one({"id": data.get("rewardId")})
            if not reward or reward.get("groupId") != current_user.get("groupId"): return PlainTextResponse(content="Forbidden", status_code=403)
            await db.requests.insert_one({"id": data["id"], "userId": data["userId"], "rewardId": data["rewardId"], "groupId": data["groupId"], "status": "PENDING", "timestamp": now, "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)
            logger.info(f"AUDIT: User {current_user['name']} requested '{reward['title']}'")

        elif action == "authorizeRequest":
            req_doc = await db.requests.find_one({"id": data["requestId"]})
            if req_doc and same_group(current_user, req_doc.get("groupId")):
                target = await db.users.find_one({"id": req_doc["userId"]})
                reward = await db.rewards.find_one({"id": req_doc["rewardId"]})
                res = await db.requests.update_one({"id": data["requestId"], "status": "PENDING"}, {"$set": {"status": "APPROVED" if data["approved"] else "REJECTED", "updatedAt": now}})
                if res.modified_count > 0:
                    await manager.notify_user(req_doc["userId"], "CELEBRATE" if data["approved"] else "REFRESH")
                    await manager.notify_group(req_doc["groupId"], "REFRESH", db)
                    if data["approved"]:
                        await db.activity.insert_one({"userId": req_doc["userId"], "groupId": reward["groupId"], "title": reward["title"], "type": "REWARD", "timestamp": now, "points": abs(int(reward["pointCost"])), "tagId": reward.get("tagId"), "performedById": current_user.get("id"), "performedBy": current_user.get("name")})
                        await db.users.update_one({"id": req_doc["userId"]}, {"$inc": {"points": -abs(int(reward["pointCost"]))}, "$set": {"updatedAt": now}})
                    logger.info(f"AUDIT: Admin {current_user['name']} {'APPROVED' if data['approved'] else 'REJECTED'} request from {target['name']}")

        elif action == "updatePoints":
            target = await db.users.find_one({"id": data["userId"]})
            if not target or target.get("groupId") != current_user.get("groupId"): return PlainTextResponse(content="Forbidden", status_code=403)
            val = int(data["points"])
            await db.activity.insert_one({"userId": data["userId"], "groupId": target["groupId"], "title": data.get("reason", "Manual Adjustment"), "type": "REWARD" if val < 0 else "ACHIEVEMENT", "timestamp": now, "points": abs(val), "performedById": current_user.get("id"), "performedBy": current_user.get("name")})
            await db.users.update_one({"id": data["userId"]}, {"$inc": {"points": val}, "$set": {"updatedAt": now}})
            await manager.notify_user(data["userId"], "REFRESH")
            logger.info(f"AUDIT: Admin {current_user['name']} manually adjusted {target['name']}\'s points by {val:+d}")

        elif action == "delete":
            col_map = {"Tags": db.tags, "Achievements": db.achievements, "Rewards": db.rewards, "Users": db.users}
            target_col = col_map.get(data.get("sheetName"))
            if target_col is not None:
                item = await target_col.find_one({"id": data["id"]})
                if item and same_group(current_user, item.get("groupId")):
                    await target_col.delete_one({"id": data["id"]})
                    await manager.notify_group(item["groupId"], "REFRESH", db)
                    logger.info(f"AUDIT: Admin {current_user['name']} deleted {data.get('sheetName')} item: {data['id']}")

        elif action == "editGroup":
            if data.get("id") != current_user.get("groupId"): return PlainTextResponse(content="Forbidden", status_code=403)
            await db.groups.update_one({"id": data["id"]}, {"$set": {"name": data["groupName"], "updatedAt": now}})
            await manager.notify_group(data["id"], "REFRESH", db)
            logger.info(f"AUDIT: Admin {current_user['name']} renamed group to '{data['groupName']}'")

        elif action == "changePassword":
            target = await db.users.find_one({"id": data["id"]})
            if not target or target.get("groupId") != current_user.get("groupId") or (data.get("id") != current_user.get("id") and not is_admin(current_user)):
                return PlainTextResponse(content="Forbidden", status_code=403)
            await db.users.update_one({"id": data["id"]}, {"$set": {"password": get_password_hash(data["password"]), "updatedAt": now}, "$inc": {"authVersion": 1}})
            logger.info(f"AUDIT: Password changed for user {target['name']}")

        return PlainTextResponse(content="Success")
    except Exception:
        logger.exception("POST /exec failed")
        return PlainTextResponse(content="Internal Server Error", status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT, access_log=False)