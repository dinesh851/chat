from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, status, File, UploadFile, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Dict, Optional
import json
import hashlib
import secrets
import jwt
from datetime import datetime, timedelta
import asyncio
import uuid
import os
import shutil
import mimetypes
import aiofiles
from pathlib import Path
from datetime import datetime, timedelta, timezone

app = FastAPI(title="Secure Chat App with File Sharing", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
MAX_USERS = 6
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {
    '.txt', '.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.gif', 
    '.mp4', '.mp3', '.wav', '.zip', '.rar', '.xls', '.xlsx', '.ppt', '.pptx', '.html', '.xml', '.txt'
}

security = HTTPBearer()

class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserProfile(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    online_status: bool = False
    last_seen: Optional[datetime] = None

class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    bio: Optional[str] = None

class MessageCreate(BaseModel):
    content: str
    recipient_id: Optional[str] = None

class FileInfo(BaseModel):
    id: str
    filename: str
    original_filename: str
    file_size: int
    file_type: str
    upload_date: datetime
    uploader_id: str
    uploader_username: str

class Message(BaseModel):
    id: str
    sender_id: str
    sender_username: str
    content: str
    timestamp: datetime
    recipient_id: Optional[str] = None
    message_type: str = "text"
    file_info: Optional[FileInfo] = None

class DatabaseManager:
    def __init__(self):
        self.users_file = "users.json"
        self.messages_file = "messages.json"
        self.files_file = "files.json"
        self.ensure_files_exist()
    
    def ensure_files_exist(self):
        if not os.path.exists(self.users_file):
            self.save_json_data(self.users_file, {})
        if not os.path.exists(self.messages_file):
            self.save_json_data(self.messages_file, [])
        if not os.path.exists(self.files_file):
            self.save_json_data(self.files_file, {})
    
    def save_json_data(self, filename: str, data: dict or list):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)
    
    def load_json_data(self, filename: str) -> dict or list:
        try:
            with open(filename, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {} if filename.endswith(("users.json", "files.json")) else []
    
    def create_user(self, user_data: UserCreate) -> dict:
        users = self.load_json_data(self.users_file)
        
        if user_data.username in users:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        password_hash = hashlib.sha256(user_data.password.encode()).hexdigest()
        
        user = {
            "id": str(uuid.uuid4()),
            "username": user_data.username,
            "password_hash": password_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "online_status": False,
            "last_seen": None
        }
        
        users[user_data.username] = user
        self.save_json_data(self.users_file, users)
        return user
    
    def authenticate_user(self, username: str, password: str) -> dict:
        users = self.load_json_data(self.users_file)
        user = users.get(username)
        
        if not user:
            return None
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if user["password_hash"] != password_hash:
            return None
        
        return user
    
    def get_user_by_username(self, username: str) -> dict:
        users = self.load_json_data(self.users_file)
        return users.get(username)
    
    def update_user_profile(self, username: str, update_data: ProfileUpdate) -> dict:
        users = self.load_json_data(self.users_file)
        user = users.get(username)
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        if update_data.full_name is not None:
            user["full_name"] = update_data.full_name
        if update_data.avatar_url is not None:
            user["avatar_url"] = update_data.avatar_url
        if update_data.bio is not None:
            user["bio"] = update_data.bio
        
        users[username] = user
        self.save_json_data(self.users_file, users)
        return user
    
    def update_user_status(self, username: str, online_status: bool):
        users = self.load_json_data(self.users_file)
        user = users.get(username)
        
        if user:
            user["online_status"] = online_status
            user["last_seen"] = datetime.now().isoformat() if not online_status else None
            users[username] = user
            self.save_json_data(self.users_file, users)
    
    def get_all_users(self) -> List[dict]:
        users = self.load_json_data(self.users_file)
        return list(users.values())
    
    def get_online_users(self) -> List[dict]:
        users = self.load_json_data(self.users_file)
        return [user for user in users.values() if user.get("online_status", False)]
    
    def save_message(self, message: dict):
        messages = self.load_json_data(self.messages_file)
        messages.append(message)
        self.save_json_data(self.messages_file, messages)
    
    def get_messages(self, limit: int = 50) -> List[dict]:
        messages = self.load_json_data(self.messages_file)
        return messages[-limit:] if len(messages) > limit else messages
    
    def save_file_info(self, file_info: FileInfo):
        files = self.load_json_data(self.files_file)
        file_dict = file_info.dict()
        file_dict["upload_date"] = file_dict["upload_date"].isoformat()
        files[file_info.id] = file_dict
        self.save_json_data(self.files_file, files)
    
    def get_file_info(self, file_id: str) -> dict:
        files = self.load_json_data(self.files_file)
        return files.get(file_id)

db = DatabaseManager()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_current_user(username: str = Depends(verify_token)):
    user = db.get_user_by_username(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user

def get_file_extension(filename: str) -> str:
    return Path(filename).suffix.lower()

def is_allowed_file(filename: str) -> bool:
    return get_file_extension(filename) in ALLOWED_EXTENSIONS

def get_file_type(filename: str) -> str:
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type:
        if mime_type.startswith('image/'):
            return 'image'
        elif mime_type.startswith('video/'):
            return 'video'
        elif mime_type.startswith('audio/'):
            return 'audio'
        elif mime_type.startswith('text/'):
            return 'text'
        elif 'pdf' in mime_type:
            return 'pdf'
        elif 'word' in mime_type or 'document' in mime_type:
            return 'document'
        elif 'spreadsheet' in mime_type or 'excel' in mime_type:
            return 'spreadsheet'
        elif 'presentation' in mime_type or 'powerpoint' in mime_type:
            return 'presentation'
        elif 'zip' in mime_type or 'rar' in mime_type:
            return 'archive'
    return 'file'

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        self.active_connections[username] = websocket
        db.update_user_status(username, True)
        await self.broadcast_user_status(username, True)
        await self.broadcast_user_list()
    
    def disconnect(self, username: str):
        if username in self.active_connections:
            del self.active_connections[username]
        db.update_user_status(username, False)
        asyncio.create_task(self.broadcast_user_status(username, False))
        asyncio.create_task(self.broadcast_user_list())
    
    async def send_personal_message(self, message: str, username: str):
        if username in self.active_connections:
            websocket = self.active_connections[username]
            await websocket.send_text(message)
    
    async def broadcast(self, message: str):
        for connection in self.active_connections.values():
            await connection.send_text(message)
    
    async def broadcast_user_status(self, username: str, online: bool):
        status_message = {
            "type": "user_status",
            "username": username,
            "online": online,
            "timestamp": datetime.now().isoformat()
        }
        await self.broadcast(json.dumps(status_message))
    
    async def broadcast_user_list(self):
        users = db.get_all_users()
        user_list_message = {
            "type": "user_list",
            "users": users
        }
        await self.broadcast(json.dumps(user_list_message))

manager = ConnectionManager()

@app.post("/api/register")
async def register(user: UserCreate):
    try:
        new_user = db.create_user(user)
        return {
            "message": "User created successfully",
            "user": {
                "username": new_user["username"]
            }
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/login")
async def login(user: UserLogin):
    authenticated_user = db.authenticate_user(user.username, user.password)
    if not authenticated_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": authenticated_user["username"]}, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": authenticated_user["username"]
        }
    }

@app.get("/api/profile")
async def get_profile(current_user: dict = Depends(get_current_user)):
    return UserProfile(
        username=current_user["username"],
        email=current_user.get("email", ""),
        full_name=current_user.get("full_name"),
        avatar_url=current_user.get("avatar_url"),
        bio=current_user.get("bio", ""),
        online_status=current_user.get("online_status", False),
        last_seen=current_user.get("last_seen")
    )

@app.put("/api/profile")
async def update_profile(
    profile_update: ProfileUpdate,
    current_user: dict = Depends(get_current_user)
):
    updated_user = db.update_user_profile(current_user["username"], profile_update)
    return {
        "message": "Profile updated successfully",
        "user": {
            "username": updated_user["username"],
            "email": updated_user.get("email", ""),
            "full_name": updated_user.get("full_name"),
            "avatar_url": updated_user.get("avatar_url"),
            "bio": updated_user.get("bio", "")
        }
    }

@app.get("/api/users")
async def get_users(current_user: dict = Depends(get_current_user)):
    users = db.get_all_users()
    return [
        {
            "id": user["id"],
            "username": user["username"],
            "full_name": user.get("full_name"),
            "avatar_url": user.get("avatar_url"),
            "online_status": user.get("online_status", False),
            "last_seen": user.get("last_seen")
        }
        for user in users
    ]

@app.get("/api/messages")
async def get_messages(
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    messages = db.get_messages(limit)
    return messages

@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    if file.size > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB")
    
    if not is_allowed_file(file.filename):
        raise HTTPException(status_code=400, detail="File type not allowed")
    
    file_id = str(uuid.uuid4())
    file_extension = get_file_extension(file.filename)
    unique_filename = f"{file_id}{file_extension}"
    file_path = UPLOAD_DIR / unique_filename
    
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")
    
    file_info = FileInfo(
        id=file_id,
        filename=unique_filename,
        original_filename=file.filename,
        file_size=file.size,
        file_type=get_file_type(file.filename),
        upload_date=datetime.now(),
        uploader_id=current_user["id"],
        uploader_username=current_user["username"]
    )
    
    db.save_file_info(file_info)
    
    return {
        "message": "File uploaded successfully",
        "file_info": file_info.dict()
    }

@app.get("/api/download/{file_id}")
async def download_file(file_id: str, current_user: dict = Depends(get_current_user)):
    file_info = db.get_file_info(file_id)
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found")
    
    file_path = UPLOAD_DIR / file_info["filename"]
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found on disk")
    
    return FileResponse(
        path=file_path,
        filename=file_info["original_filename"],
        media_type='application/octet-stream'
    )

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    user = db.get_user_by_username(username)
    if not user:
        await websocket.close(code=1008)
        return
    
    await manager.connect(websocket, username)
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            timestamp = datetime.now(timezone.utc)
            
            if message_data.get("type") == "file_message":
                file_id = message_data.get("file_id")
                file_info = db.get_file_info(file_id)
                
                if not file_info:
                    continue
                
                message = {
                    "id": str(uuid.uuid4()),
                    "sender_id": user["id"],
                    "sender_username": username,
                    "content": f"📎 {file_info['original_filename']}",
                    "timestamp": timestamp,
                    "message_type": "file",
                    "file_info": file_info
                }
            else:
                message = {
                    "id": str(uuid.uuid4()),
                    "sender_id": user["id"],
                    "sender_username": username,
                    "content": message_data["content"],
                    "timestamp": timestamp,
                    "message_type": "text"
                }
            
            db.save_message(message)
            
            broadcast_message = {
                "type": "message",
                **message
            }
            broadcast_message["timestamp"] = message["timestamp"].isoformat()
            
            if "file_info" in broadcast_message:
                broadcast_message["file_info"]["upload_date"] = message["file_info"]["upload_date"].isoformat()
            
            await manager.broadcast(json.dumps(broadcast_message))
                
    except WebSocketDisconnect:
        manager.disconnect(username)
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(username)

@app.get("/")
async def get():
    return HTMLResponse(content=open("index1.html", encoding="utf-8").read(), status_code=200)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)