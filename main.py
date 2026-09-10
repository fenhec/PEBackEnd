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

# MONGO_URI = os.getenv("MONGO_URI")
# DB_NAME = os.getenv("MONGO_DB")
# JWT_SECRET = os.getenv("JWT_SECRET")
# API_HOST = os.getenv("API_HOST", "0.0.0.0")
# API_PORT = int(os.getenv("API_PORT", "8088"))
ALGORITHM = "HS256"
MONGO_URI = os.getenv("MONGO_URI", "mongodb://192.168.1.118:27018/")
API_HOST = os.getenv("API_HOST", "0.0.0.0")
DB_NAME = os.getenv("MONGO_DB", "pointexchange")
API_PORT = int(os.getenv("API_PORT", "8088"))
ALGORITHM = "HS256"
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET must be set in the server environment or .env file")
JWT_SECRET="point_exchange_super_secure_and_very_long_secret_key_2026_!@#"

# 2. REAL-TIME CONNECTION MANAGER
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket
        logger.info(f"WebSocket Connected: User {user_id}")

    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
            logger.info(f"WebSocket Disconnected: User {user_id}")

    async def notify_user(self, user_id: str, message: str):
        if user_id in self.active_connections:
            try:
                await self.active_connections[user_id].send_text(message)
                logger.info(f"Real-time signal '{message}' sent to user {user_id}")
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
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False


def create_access_token(data: dict):
    to_encode = data.copy()
    now_utc = datetime.utcnow()
    expire = now_utc + timedelta(days=30)
    to_encode.update({"iat": now_utc, "exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)


def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except Exception:
        return None


async def get_current_user_from_request(request: Request):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        return None
    token_data = decode_token(auth.split(" ", 1)[1])
    if not token_data or not token_data.get("sub"):
        return None
    user = await db.users.find_one({"id": token_data["sub"]})
    if not user:
        return None
    # Password changes invalidate previously issued tokens without any client change.
    if int(token_data.get("ver", 0)) != int(user.get("authVersion", 0)):
        return None
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
            if col not in await db.list_collection_names():
                await db.create_collection(col)
        logger.info("Database Ready.")
    except Exception as e:
        logger.error(f"STARTUP ERROR: {e}")
    yield
    client.close()


# app = FastAPI(title="PointExchange Optimized Backend", lifespan=lifespan)

app = FastAPI(
    title="PointExchange Optimized Backend",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)


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
    await manager.connect(user_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(user_id)


# 6. HELPERS (Optimized with Pagination)
async def get_populated_user(user_doc: Dict, limit: int = 20, offset: int = 0):
    user_id = user_doc["id"]
    # PAGINATION: Fetch history items in chunks (default 20)
    activity = await db.activity.find({"userId": user_id}).sort("timestamp", -1).skip(offset).limit(limit).to_list(
        length=limit)
    earned, redeemed = [], []
    for act in activity:
        event = {"title": act["title"], "timestamp": int(act["timestamp"]), "points": abs(int(act.get("points", 0))),
                 "tagId": act.get("tagId")}
        if act["type"] == 'ACHIEVEMENT':
            earned.append(event)
        else:
            redeemed.append(event)
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
        # Get optional pagination/sync params
        params = request.query_params
        last_sync = max(0, int(params.get("lastSync", 0)))
        act_limit = max(1, min(int(params.get("activityLimit", 20)), 100))
        act_offset = max(0, int(params.get("activityOffset", 0)))

        if action == "login":
            if not email or not password:
                return JSONResponse(content="Error")
            client_ip = request.client.host if request.client else "unknown"
            cutoff = time.time() - LOGIN_WINDOW_SECONDS
            attempts = [t for t in login_attempts.get(client_ip, []) if t > cutoff]
            if len(attempts) >= LOGIN_MAX_ATTEMPTS:
                return PlainTextResponse(content="Too Many Requests", status_code=429)
            user = await db.users.find_one({"email": email.lower().strip()})
            if not user or not verify_password(password, user["password"]):
                attempts.append(time.time())
                login_attempts[client_ip] = attempts
                return JSONResponse(content="Error")
            login_attempts.pop(client_ip, None)
            token = create_access_token({"sub": user["id"], "email": user["email"],
                                         "ver": int(user.get("authVersion", 0))})
            populated = await get_populated_user(user, limit=act_limit, offset=act_offset)
            populated["token"] = token
            group = await db.groups.find_one({"id": user["groupId"]})
            if group and "_id" in group: del group["_id"]
            return JSONResponse(content={"user": populated,
                                         "group": group or {"id": user["groupId"], "name": "Default Group",
                                                            "ownerAdminId": user["id"]}})

        current_user = await get_current_user_from_request(request)

        if action == "getEmails":
            if not is_admin(current_user):
                return PlainTextResponse(content="Forbidden", status_code=403)
            users = await db.users.find({"groupId": current_user["groupId"]}, {"email": 1}).to_list(length=5000)
            return PlainTextResponse(content=",".join([u["email"] for u in users]))

        if not current_user:
            return PlainTextResponse(content="Unauthorized", status_code=401)

        if action == "getData":
            if groupId == "validate":
                if not userId:
                    return PlainTextResponse(content="Unauthorized", status_code=401)
                user = await db.users.find_one({"email": userId.lower().strip()})
                if not user or user.get("groupId") != current_user.get("groupId"):
                    return PlainTextResponse(content="Unauthorized", status_code=401)
                group = await db.groups.find_one({"id": user["groupId"]})
                if group and "_id" in group: del group["_id"]
                return JSONResponse(content={"user": await get_populated_user(user, limit=act_limit, offset=act_offset),
                                             "group": group})

            if not same_group(current_user, groupId):
                return PlainTextResponse(content="Forbidden", status_code=403)

            # DELTA SYNC: Only fetch items changed since last_sync
            sync_query = {"groupId": groupId}
            if last_sync > 0:
                sync_query["updatedAt"] = {"$gt": last_sync}

            all_users_for_rank = await db.users.find({"groupId": groupId}).to_list(length=1000)
            my_rank = 0
            if userId:
                sorted_users = sorted(all_users_for_rank, key=lambda x: x.get("points", 0), reverse=True)
                for i, u in enumerate(sorted_users):
                    if u["id"] == userId: my_rank = i + 1; break

            # Delta logic for collection fetching
            users_list = []
            if includeUsers == "true":
                # For users we always fetch changed ones. If last_sync=0, fetches all.
                users_docs = await db.users.find(sync_query).to_list(length=1000)
                users_list = [await get_populated_user(u, limit=act_limit, offset=act_offset) for u in users_docs]

            achievements = await db.achievements.find(sync_query).to_list(1000)
            rewards = await db.rewards.find(sync_query).to_list(1000)
            requests = await db.requests.find(sync_query).to_list(1000)
            tags = await db.tags.find(sync_query).to_list(1000)

            for coll in [achievements, rewards, requests, tags]:
                for item in coll:
                    if "_id" in item: del item["_id"]

            return JSONResponse(content={
                "users": users_list,
                "achievements": achievements,
                "rewards": rewards,
                "requests": requests,
                "tags": tags,
                "rank": my_rank,
                "serverTime": int(time.time() * 1000)
            })

        # New action for endless scrolling in UI
        if action == "getActivity":
            target_user = await db.users.find_one({"id": userId})
            if not target_user or target_user.get("groupId") != current_user.get("groupId"):
                return PlainTextResponse(content="Forbidden", status_code=403)
            activity_docs = await db.activity.find({"userId": userId}).sort("timestamp", -1).skip(act_offset).limit(
                act_limit).to_list(length=act_limit)
            return JSONResponse(content=[
                {"title": a["title"], "timestamp": int(a["timestamp"]), "points": abs(int(a.get("points", 0))),
                 "tagId": a.get("tagId"), "type": a["type"]} for a in activity_docs])

    except Exception:
        logger.exception("GET /exec failed")
        return PlainTextResponse(content="Internal Server Error", status_code=500)


# 8. POST ACTIONS (Updated with delta-sync timestamps)
@app.post("/exec")
async def handle_post(request: Request):
    try:
        data = await request.json()
        action = data.get("action")
        now = int(time.time() * 1000)
        logger.info(f"POST: {action}")

        current_user = None
        if action != "registerAdmin":
            current_user = await get_current_user_from_request(request)
            if not current_user:
                return PlainTextResponse(content="Unauthorized", status_code=401)

        admin_actions = {"addUser", "editUser", "addTag", "editTag", "addAchievement", "editAchievement",
                         "awardAchievement", "addReward", "editReward", "authorizeRequest", "editGroup",
                         "updatePoints", "delete"}
        if action in admin_actions and not is_admin(current_user):
            return PlainTextResponse(content="Forbidden", status_code=403)

        if current_user:
            logger.info(f"AUDIT: user={current_user.get('name')} id={current_user.get('id')} action={action}")

        if action in ["registerAdmin", "addUser"]:
            if await db.users.find_one({"email": data.get("email", "").lower().strip()}): return PlainTextResponse(
                content="Error: Email exists")

        if action == "registerAdmin":
            h_pass = get_password_hash(data["password"])
            await db.groups.insert_one(
                {"id": data["groupId"], "name": data["groupName"], "ownerAdminId": data["adminId"], "updatedAt": now})
            await db.users.insert_one({"id": data["adminId"], "groupId": data["groupId"], "name": data["name"],
                                       "email": data["email"].lower().strip(), "password": h_pass, "role": "ADMIN",
                                       "points": 0, "authVersion": 0, "updatedAt": now})

        elif action == "addUser":
            if not same_group(current_user, data.get("groupId")):
                return PlainTextResponse(content="Forbidden", status_code=403)
            h_pass = get_password_hash(data["password"])
            await db.users.insert_one({"id": data["id"], "groupId": data["groupId"], "name": data["name"],
                                       "email": data["email"].lower().strip(), "password": h_pass, "role": data["role"],
                                       "points": 0, "authVersion": 0, "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)

        elif action == "editUser":
            target_user = await db.users.find_one({"id": data["id"]})
            if not target_user or target_user.get("groupId") != current_user.get("groupId"):
                return PlainTextResponse(content="Forbidden", status_code=403)
            await db.users.update_one({"id": data["id"]}, {
                "$set": {"name": data["name"], "email": data["email"].lower().strip(), "role": data["role"],
                         "updatedAt": now}})
            await manager.notify_user(data["id"], "REFRESH")

        elif action == "addTag":
            if not same_group(current_user, data.get("groupId")):
                return PlainTextResponse(content="Forbidden", status_code=403)
            await db.tags.insert_one(
                {"id": data["id"], "groupId": data["groupId"], "name": data["name"], "colorHex": data["colorHex"],
                 "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)

        elif action == "editTag":
            existing = await db.tags.find_one({"id": data["id"]})
            if not existing or existing.get("groupId") != current_user.get("groupId"):
                return PlainTextResponse(content="Forbidden", status_code=403)
            tag = await db.tags.find_one({"id": data["id"]})
            await db.tags.update_one({"id": data["id"]},
                                     {"$set": {"name": data["name"], "colorHex": data["colorHex"], "updatedAt": now}})
            if tag: await manager.notify_group(tag["groupId"], "REFRESH", db)

        elif action == "addAchievement":
            if not same_group(current_user, data.get("groupId")):
                return PlainTextResponse(content="Forbidden", status_code=403)
            await db.achievements.insert_one({"id": data["id"], "groupId": data["groupId"], "title": data["title"],
                                              "description": data["description"], "points": int(data["points"]),
                                              "tagId": data.get("tagId"), "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)

        elif action == "editAchievement":
            existing = await db.achievements.find_one({"id": data["id"]})
            if not existing or existing.get("groupId") != current_user.get("groupId"):
                return PlainTextResponse(content="Forbidden", status_code=403)
            await db.achievements.update_one({"id": data["id"]}, {
                "$set": {"title": data["title"], "description": data["description"], "points": int(data["points"]),
                         "tagId": data.get("tagId"), "updatedAt": now}})
            ach = await db.achievements.find_one({"id": data["id"]})
            if ach: await manager.notify_group(ach["groupId"], "REFRESH", db)

        elif action == "awardAchievement":
            ach = await db.achievements.find_one({"id": data["achievementId"]})
            target_user = await db.users.find_one({"id": data["userId"]})
            if not ach or not target_user or ach.get("groupId") != current_user.get("groupId") or target_user.get("groupId") != current_user.get("groupId"):
                return PlainTextResponse(content="Forbidden", status_code=403)
            if ach:
                await db.activity.insert_one(
                    {"userId": data["userId"], "groupId": ach["groupId"], "title": ach["title"], "type": "ACHIEVEMENT",
                     "timestamp": now, "points": abs(int(ach["points"])), "tagId": ach.get("tagId"),
                     "performedById": current_user.get("id"), "performedBy": current_user.get("name")})
                await db.users.update_one({"id": data["userId"]},
                                          {"$inc": {"points": int(ach["points"])}, "$set": {"updatedAt": now}})
                await manager.notify_user(data["userId"], "REFRESH")

        elif action == "addReward":
            if not same_group(current_user, data.get("groupId")):
                return PlainTextResponse(content="Forbidden", status_code=403)
            await db.rewards.insert_one({"id": data["id"], "groupId": data["groupId"], "title": data["title"],
                                         "description": data["description"], "pointCost": int(data["pointCost"]),
                                         "cooldownDays": int(data.get("cooldownDays", 0)), "tagId": data.get("tagId"),
                                         "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)

        elif action == "editReward":
            existing = await db.rewards.find_one({"id": data["id"]})
            if not existing or existing.get("groupId") != current_user.get("groupId"):
                return PlainTextResponse(content="Forbidden", status_code=403)
            await db.rewards.update_one({"id": data["id"]}, {
                "$set": {"title": data["title"], "description": data["description"],
                         "pointCost": int(data["pointCost"]), "cooldownDays": int(data.get("cooldownDays", 0)),
                         "tagId": data.get("tagId"), "updatedAt": now}})
            reward = await db.rewards.find_one({"id": data["id"]})
            if reward: await manager.notify_group(reward["groupId"], "REFRESH", db)

        elif action == "addRequest":
            if not same_group(current_user, data.get("groupId")) or data.get("userId") != current_user.get("id"):
                return PlainTextResponse(content="Forbidden", status_code=403)
            reward = await db.rewards.find_one({"id": data.get("rewardId")})
            if not reward or reward.get("groupId") != current_user.get("groupId"):
                return PlainTextResponse(content="Forbidden", status_code=403)
            await db.requests.insert_one(
                {"id": data["id"], "userId": data["userId"], "rewardId": data["rewardId"], "groupId": data["groupId"],
                 "status": "PENDING", "timestamp": now, "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)

        elif action == "authorizeRequest":
            req_doc = await db.requests.find_one({"id": data["requestId"]})
            if req_doc:
                if req_doc.get("groupId") != current_user.get("groupId"):
                    return PlainTextResponse(content="Forbidden", status_code=403)

                target_user = await db.users.find_one({"id": req_doc.get("userId")})
                reward = await db.rewards.find_one({"id": req_doc.get("rewardId")})
                if (not target_user or not reward or
                        target_user.get("groupId") != current_user.get("groupId") or
                        reward.get("groupId") != current_user.get("groupId")):
                    return PlainTextResponse(content="Forbidden", status_code=403)

                # Only a pending request may transition. The status filter makes the
                # transition atomic so concurrent approvals cannot deduct points twice.
                result = await db.requests.update_one(
                    {"id": data["requestId"], "status": "PENDING"},
                    {"$set": {"status": "APPROVED" if data["approved"] else "REJECTED", "updatedAt": now}}
                )
                if result.modified_count == 0:
                    return PlainTextResponse(content="Request already processed", status_code=409)

                await manager.notify_user(req_doc["userId"], "CELEBRATE" if data["approved"] else "REFRESH")
                await manager.notify_group(req_doc["groupId"], "REFRESH", db)
                if data["approved"]:
                    await db.activity.insert_one(
                        {"userId": req_doc["userId"], "groupId": reward["groupId"], "title": reward["title"],
                         "type": "REWARD", "timestamp": now, "points": abs(int(reward["pointCost"])),
                         "tagId": reward.get("tagId"), "performedById": current_user.get("id"),
                         "performedBy": current_user.get("name")})
                    await db.users.update_one({"id": req_doc["userId"]},
                                              {"$inc": {"points": -abs(int(reward["pointCost"]))},
                                               "$set": {"updatedAt": now}})

        elif action == "editGroup":
            if data.get("id") != current_user.get("groupId"):
                return PlainTextResponse(content="Forbidden", status_code=403)
            await db.groups.update_one({"id": data["id"]}, {"$set": {"name": data["groupName"], "updatedAt": now}})
            await manager.notify_group(data["id"], "REFRESH", db)

        elif action == "changePassword":
            target_user = await db.users.find_one({"id": data["id"]})
            if not target_user or target_user.get("groupId") != current_user.get("groupId") or (data.get("id") != current_user.get("id") and not is_admin(current_user)):
                return PlainTextResponse(content="Forbidden", status_code=403)
            await db.users.update_one({"id": data["id"]},
                                      {"$set": {"password": get_password_hash(data["password"]), "updatedAt": now},
                                       "$inc": {"authVersion": 1}})

        elif action == "updatePoints":
            target_user = await db.users.find_one({"id": data["userId"]})
            if not target_user or target_user.get("groupId") != current_user.get("groupId"):
                return PlainTextResponse(content="Forbidden", status_code=403)
            val = int(data["points"])
            await db.activity.insert_one({"userId": data["userId"], "groupId": target_user["groupId"],
                                          "title": data.get("reason", "Manual Adjustment"),
                                          "type": "REWARD" if val < 0 else "ACHIEVEMENT", "timestamp": now,
                                          "points": abs(val), "performedById": current_user.get("id"),
                                          "performedBy": current_user.get("name")})
            await db.users.update_one({"id": data["userId"]}, {"$inc": {"points": val}, "$set": {"updatedAt": now}})
            await manager.notify_user(data["userId"], "REFRESH")

        elif action == "delete":
            col_map = {"Tags": db.tags, "Achievements": db.achievements, "Rewards": db.rewards, "Users": db.users}
            target_col = col_map.get(data.get("sheetName"))
            if target_col is not None:
                item = await target_col.find_one({"id": data["id"]})
                if not item or item.get("groupId") != current_user.get("groupId"):
                    return PlainTextResponse(content="Forbidden", status_code=403)
                await target_col.delete_one({"id": data["id"]})
                if item and "groupId" in item: await manager.notify_group(item["groupId"], "REFRESH", db)

        return PlainTextResponse(content="Success")
    except Exception:
        logger.exception("POST /exec failed")
        return PlainTextResponse(content="Internal Server Error", status_code=500)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=API_HOST, port=API_PORT, access_log=False)