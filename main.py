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
MONGO_URI="mongodb://192.168.1.118:27018/"
API_HOST="0.0.0.0"
DB_NAME = "pointexchange"
API_PORT = 8088
ALGORITHM = "HS256"
JWT_SECRET="point_exchange_super_secure_and_very_long_secret_key_2026_!@#"



print(MONGO_URI)
print(DB_NAME)
print(API_HOST)
print(MONGO_URI)

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
    expire = datetime.utcnow() + timedelta(days=30)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)


def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except Exception:
        return None


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


app = FastAPI(title="PointExchange Optimized Backend", lifespan=lifespan)


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
        last_sync = int(params.get("lastSync", 0))
        act_limit = int(params.get("activityLimit", 20))
        act_offset = int(params.get("activityOffset", 0))

        if action == "login":
            user = await db.users.find_one({"email": email.lower().strip()})
            if not user or not verify_password(password, user["password"]): return JSONResponse(content="Error")
            token = create_access_token({"sub": user["id"], "email": user["email"]})
            populated = await get_populated_user(user, limit=act_limit, offset=act_offset)
            populated["token"] = token
            group = await db.groups.find_one({"id": user["groupId"]})
            if group and "_id" in group: del group["_id"]
            return JSONResponse(content={"user": populated,
                                         "group": group or {"id": user["groupId"], "name": "Default Group",
                                                            "ownerAdminId": user["id"]}})

        if action == "getEmails":
            users = await db.users.find({}, {"email": 1}).to_list(length=5000)
            return PlainTextResponse(content=",".join([u["email"] for u in users]))

        auth = request.headers.get("Authorization")
        if not auth or not decode_token(auth.split(" ")[1]): return PlainTextResponse(content="Unauthorized",
                                                                                      status_code=401)

        if action == "getData":
            if groupId == "validate":
                user = await db.users.find_one({"email": userId.lower().strip()})
                if not user: return PlainTextResponse(content="Unauthorized", status_code=401)
                group = await db.groups.find_one({"id": user["groupId"]})
                if group and "_id" in group: del group["_id"]
                return JSONResponse(content={"user": await get_populated_user(user, limit=act_limit, offset=act_offset),
                                             "group": group})

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
            activity_docs = await db.activity.find({"userId": userId}).sort("timestamp", -1).skip(act_offset).limit(
                act_limit).to_list(length=act_limit)
            return JSONResponse(content=[
                {"title": a["title"], "timestamp": int(a["timestamp"]), "points": abs(int(a.get("points", 0))),
                 "tagId": a.get("tagId"), "type": a["type"]} for a in activity_docs])

    except Exception as e:
        return PlainTextResponse(content=f"Error: {e}", status_code=500)


# 8. POST ACTIONS (Updated with delta-sync timestamps)
@app.post("/exec")
async def handle_post(request: Request):
    try:
        data = await request.json()
        action = data.get("action")
        now = int(time.time() * 1000)
        logger.info(f"POST: {action}")

        if action != "registerAdmin":
            auth = request.headers.get("Authorization")
            if not auth or not decode_token(auth.split(" ")[1]): return PlainTextResponse(content="Unauthorized",
                                                                                          status_code=401)

        if action in ["registerAdmin", "addUser"]:
            if await db.users.find_one({"email": data.get("email", "").lower().strip()}): return PlainTextResponse(
                content="Error: Email exists")

        if action == "registerAdmin":
            h_pass = get_password_hash(data["password"])
            await db.groups.insert_one(
                {"id": data["groupId"], "name": data["groupName"], "ownerAdminId": data["adminId"], "updatedAt": now})
            await db.users.insert_one({"id": data["adminId"], "groupId": data["groupId"], "name": data["name"],
                                       "email": data["email"].lower().strip(), "password": h_pass, "role": "ADMIN",
                                       "points": 0, "updatedAt": now})

        elif action == "addUser":
            h_pass = get_password_hash(data["password"])
            await db.users.insert_one({"id": data["id"], "groupId": data["groupId"], "name": data["name"],
                                       "email": data["email"].lower().strip(), "password": h_pass, "role": data["role"],
                                       "points": 0, "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)

        elif action == "editUser":
            await db.users.update_one({"id": data["id"]}, {
                "$set": {"name": data["name"], "email": data["email"].lower().strip(), "role": data["role"],
                         "updatedAt": now}})
            await manager.notify_user(data["id"], "REFRESH")

        elif action == "addTag":
            await db.tags.insert_one(
                {"id": data["id"], "groupId": data["groupId"], "name": data["name"], "colorHex": data["colorHex"],
                 "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)

        elif action == "editTag":
            tag = await db.tags.find_one({"id": data["id"]})
            await db.tags.update_one({"id": data["id"]},
                                     {"$set": {"name": data["name"], "colorHex": data["colorHex"], "updatedAt": now}})
            if tag: await manager.notify_group(tag["groupId"], "REFRESH", db)

        elif action == "addAchievement":
            await db.achievements.insert_one({"id": data["id"], "groupId": data["groupId"], "title": data["title"],
                                              "description": data["description"], "points": int(data["points"]),
                                              "tagId": data.get("tagId"), "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)

        elif action == "editAchievement":
            await db.achievements.update_one({"id": data["id"]}, {
                "$set": {"title": data["title"], "description": data["description"], "points": int(data["points"]),
                         "tagId": data.get("tagId"), "updatedAt": now}})
            ach = await db.achievements.find_one({"id": data["id"]})
            if ach: await manager.notify_group(ach["groupId"], "REFRESH", db)

        elif action == "awardAchievement":
            ach = await db.achievements.find_one({"id": data["achievementId"]})
            if ach:
                await db.activity.insert_one(
                    {"userId": data["userId"], "groupId": ach["groupId"], "title": ach["title"], "type": "ACHIEVEMENT",
                     "timestamp": now, "points": abs(int(ach["points"])), "tagId": ach.get("tagId")})
                await db.users.update_one({"id": data["userId"]},
                                          {"$inc": {"points": int(ach["points"])}, "$set": {"updatedAt": now}})
                await manager.notify_user(data["userId"], "REFRESH")

        elif action == "addReward":
            await db.rewards.insert_one({"id": data["id"], "groupId": data["groupId"], "title": data["title"],
                                         "description": data["description"], "pointCost": int(data["pointCost"]),
                                         "cooldownDays": int(data.get("cooldownDays", 0)), "tagId": data.get("tagId"),
                                         "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)

        elif action == "editReward":
            await db.rewards.update_one({"id": data["id"]}, {
                "$set": {"title": data["title"], "description": data["description"],
                         "pointCost": int(data["pointCost"]), "cooldownDays": int(data.get("cooldownDays", 0)),
                         "tagId": data.get("tagId"), "updatedAt": now}})
            reward = await db.rewards.find_one({"id": data["id"]})
            if reward: await manager.notify_group(reward["groupId"], "REFRESH", db)

        elif action == "addRequest":
            await db.requests.insert_one(
                {"id": data["id"], "userId": data["userId"], "rewardId": data["rewardId"], "groupId": data["groupId"],
                 "status": "PENDING", "timestamp": now, "updatedAt": now})
            await manager.notify_group(data["groupId"], "REFRESH", db)

        elif action == "authorizeRequest":
            req_doc = await db.requests.find_one({"id": data["requestId"]})
            if req_doc:
                await db.requests.update_one({"id": data["requestId"]}, {
                    "$set": {"status": "APPROVED" if data["approved"] else "REJECTED", "updatedAt": now}})
                await manager.notify_user(req_doc["userId"], "CELEBRATE" if data["approved"] else "REFRESH")
                await manager.notify_group(req_doc["groupId"], "REFRESH", db)
                if data["approved"]:
                    reward = await db.rewards.find_one({"id": req_doc["rewardId"]})
                    if reward:
                        await db.activity.insert_one(
                            {"userId": req_doc["userId"], "groupId": reward["groupId"], "title": reward["title"],
                             "type": "REWARD", "timestamp": now, "points": abs(int(reward["pointCost"])),
                             "tagId": reward.get("tagId")})
                        await db.users.update_one({"id": req_doc["userId"]},
                                                  {"$inc": {"points": -abs(int(reward["pointCost"]))},
                                                   "$set": {"updatedAt": now}})

        elif action == "editGroup":
            await db.groups.update_one({"id": data["id"]}, {"$set": {"name": data["groupName"], "updatedAt": now}})
            await manager.notify_group(data["id"], "REFRESH", db)

        elif action == "changePassword":
            await db.users.update_one({"id": data["id"]},
                                      {"$set": {"password": get_password_hash(data["password"]), "updatedAt": now}})

        elif action == "updatePoints":
            val = int(data["points"])
            await db.activity.insert_one({"userId": data["userId"], "groupId": data.get("groupId", ""),
                                          "title": data.get("reason", "Manual Adjustment"),
                                          "type": "REWARD" if val < 0 else "ACHIEVEMENT", "timestamp": now,
                                          "points": abs(val)})
            await db.users.update_one({"id": data["userId"]}, {"$inc": {"points": val}, "$set": {"updatedAt": now}})
            await manager.notify_user(data["userId"], "REFRESH")

        elif action == "delete":
            col_map = {"Tags": db.tags, "Achievements": db.achievements, "Rewards": db.rewards, "Users": db.users}
            target_col = col_map.get(data.get("sheetName"))
            if target_col is not None:
                item = await target_col.find_one({"id": data["id"]})
                await target_col.delete_one({"id": data["id"]})
                if item and "groupId" in item: await manager.notify_group(item["groupId"], "REFRESH", db)

        return PlainTextResponse(content="Success")
    except Exception as e:
        logger.error(f"POST Error: {e}")
        return PlainTextResponse(content=f"Error: {e}", status_code=500)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=API_HOST, port=API_PORT)