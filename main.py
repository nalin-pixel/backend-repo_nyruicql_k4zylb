import os
from datetime import datetime, timedelta, date
from typing import List, Optional, Dict, Any
import hashlib
import secrets

from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Session as SessionSchema, Property as PropertySchema, Booking as BookingSchema

app = FastAPI(title="Saknli API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helpers

def hash_password(password: str) -> str:
    salt = os.getenv("PW_SALT", "saknli_salt")
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()


def to_object_id(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="معرف غير صالح")


def user_safe(u: Dict[str, Any]) -> Dict[str, Any]:
    if not u:
        return u
    u = {**u}
    u.pop("password_hash", None)
    u["id"] = str(u.pop("_id"))
    return u


async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="يرجى تسجيل الدخول")
    token = authorization.split()[1]
    session = db["session"].find_one({"token": token, "expires_at": {"$gt": datetime.utcnow()}})
    if not session:
        raise HTTPException(status_code=401, detail="انتهت الجلسة أو غير صالحة")
    user = db["user"].find_one({"_id": session["user_id"] if isinstance(session["user_id"], ObjectId) else ObjectId(session["user_id"])})
    if not user:
        raise HTTPException(status_code=401, detail="المستخدم غير موجود")
    return user_safe(user)


# Root and health
@app.get("/")
def read_root():
    return {"name": "سكنلي", "status": "ok"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()[:10]
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:80]}"
    return response


# Auth models
class SignupBody(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    role: str = "user"  # user | host | admin
    phone: Optional[str] = None
    city: Optional[str] = None


class LoginBody(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    token: str
    user: Dict[str, Any]


@app.post("/auth/signup", response_model=TokenResponse)
def signup(body: SignupBody):
    existing = db["user"].find_one({"email": body.email})
    if existing:
        raise HTTPException(status_code=400, detail="البريد الإلكتروني مستخدم مسبقاً")
    user_doc = UserSchema(
        full_name=body.full_name,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
        phone=body.phone,
        city=body.city,
    ).model_dump()
    user_id = db["user"].insert_one(user_doc).inserted_id
    token = secrets.token_urlsafe(32)
    session_doc = SessionSchema(user_id=str(user_id), token=token, expires_at=datetime.utcnow() + timedelta(days=7)).model_dump()
    session_doc["user_id"] = user_id
    db["session"].insert_one(session_doc)
    user = db["user"].find_one({"_id": user_id})
    return {"token": token, "user": user_safe(user)}


@app.post("/auth/login", response_model=TokenResponse)
def login(body: LoginBody):
    user = db["user"].find_one({"email": body.email})
    if not user or user.get("password_hash") != hash_password(body.password):
        raise HTTPException(status_code=401, detail="بيانات الدخول غير صحيحة")
    token = secrets.token_urlsafe(32)
    session_doc = SessionSchema(user_id=str(user["_id"]), token=token, expires_at=datetime.utcnow() + timedelta(days=7)).model_dump()
    session_doc["user_id"] = user["_id"]
    db["session"].insert_one(session_doc)
    return {"token": token, "user": user_safe(user)}


@app.get("/me")
async def me(user=Depends(get_current_user)):
    return user


# Properties
class PropertyCreate(BaseModel):
    title: str
    description: str
    city: str
    address: str
    type: str
    price_per_month: float
    images: List[str] = []
    lat: Optional[float] = None
    lng: Optional[float] = None
    distance_to_university: Optional[str] = None
    available_from: Optional[date] = None
    available_to: Optional[date] = None


class PropertyUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    city: Optional[str] = None
    address: Optional[str] = None
    type: Optional[str] = None
    price_per_month: Optional[float] = None
    images: Optional[List[str]] = None
    lat: Optional[float] = None
    lng: Optional[float] = None
    distance_to_university: Optional[str] = None
    available_from: Optional[date] = None
    available_to: Optional[date] = None
    is_active: Optional[bool] = None


@app.get("/properties")
def list_properties(
    city: Optional[str] = Query(None),
    type: Optional[str] = Query(None),
    min_price: Optional[float] = Query(None),
    max_price: Optional[float] = Query(None),
    start_date: Optional[date] = Query(None),
    end_date: Optional[date] = Query(None),
    limit: int = 50,
):
    q: Dict[str, Any] = {"is_active": True}
    if city:
        q["city"] = city
    if type:
        q["type"] = type
    price_cond: Dict[str, Any] = {}
    if min_price is not None:
        price_cond["$gte"] = min_price
    if max_price is not None:
        price_cond["$lte"] = max_price
    if price_cond:
        q["price_per_month"] = price_cond
    # Availability overlap check: property.available_from <= end and property.available_to >= start
    if start_date and end_date:
        q["$and"] = [
            {"$or": [{"available_from": None}, {"available_from": {"$lte": end_date}}]},
            {"$or": [{"available_to": None}, {"available_to": {"$gte": start_date}}]},
        ]
    docs = db["property"].find(q).limit(limit)
    res = []
    for d in docs:
        d["id"] = str(d.pop("_id"))
        res.append(d)
    return res


@app.get("/properties/{prop_id}")
def get_property(prop_id: str):
    d = db["property"].find_one({"_id": to_object_id(prop_id)})
    if not d:
        raise HTTPException(status_code=404, detail="السكن غير موجود")
    d["id"] = str(d.pop("_id"))
    return d


@app.post("/properties")
async def create_property(body: PropertyCreate, user=Depends(get_current_user)):
    if user.get("role") not in ["host", "admin"]:
        raise HTTPException(status_code=403, detail="صلاحيات غير كافية")
    prop = PropertySchema(**body.model_dump(), host_id=user["id"]).model_dump()
    inserted = db["property"].insert_one(prop)
    p = db["property"].find_one({"_id": inserted.inserted_id})
    p["id"] = str(p.pop("_id"))
    return p


@app.put("/properties/{prop_id}")
async def update_property(prop_id: str, body: PropertyUpdate, user=Depends(get_current_user)):
    p = db["property"].find_one({"_id": to_object_id(prop_id)})
    if not p:
        raise HTTPException(status_code=404, detail="السكن غير موجود")
    if user.get("role") != "admin" and p.get("host_id") != user.get("id"):
        raise HTTPException(status_code=403, detail="ليس لديك إذن للتعديل")
    update = {k: v for k, v in body.model_dump(exclude_none=True).items()}
    if not update:
        return {"updated": False}
    db["property"].update_one({"_id": p["_id"]}, {"$set": update, "$currentDate": {"updated_at": True}})
    p = db["property"].find_one({"_id": p["_id"]})
    p["id"] = str(p.pop("_id"))
    return p


@app.delete("/properties/{prop_id}")
async def delete_property(prop_id: str, user=Depends(get_current_user)):
    p = db["property"].find_one({"_id": to_object_id(prop_id)})
    if not p:
        raise HTTPException(status_code=404, detail="السكن غير موجود")
    if user.get("role") != "admin" and p.get("host_id") != user.get("id"):
        raise HTTPException(status_code=403, detail="ليس لديك إذن للحذف")
    db["property"].delete_one({"_id": p["_id"]})
    return {"deleted": True}


# Bookings
class BookingCreate(BaseModel):
    property_id: str
    start_date: date
    end_date: date
    guests: int = 1


@app.post("/bookings")
async def create_booking(body: BookingCreate, user=Depends(get_current_user)):
    if body.end_date < body.start_date:
        raise HTTPException(status_code=400, detail="نطاق التواريخ غير صالح")
    prop = db["property"].find_one({"_id": to_object_id(body.property_id)})
    if not prop:
        raise HTTPException(status_code=404, detail="السكن غير موجود")
    booking = BookingSchema(
        property_id=body.property_id,
        user_id=user["id"],
        start_date=body.start_date,
        end_date=body.end_date,
        guests=body.guests,
        status="pending",
    ).model_dump()
    # store ObjectId references
    booking["property_id"] = ObjectId(booking["property_id"])
    booking["user_id"] = ObjectId(booking["user_id"])
    inserted = db["booking"].insert_one(booking)
    b = db["booking"].find_one({"_id": inserted.inserted_id})
    b["id"] = str(b.pop("_id"))
    b["property_id"] = str(b["property_id"])  # stringify
    b["user_id"] = str(b["user_id"])  # stringify
    return b


@app.get("/bookings/me")
async def my_bookings(user=Depends(get_current_user)):
    cur = db["booking"].find({"user_id": ObjectId(user["id"])})
    res = []
    for b in cur:
        b["id"] = str(b.pop("_id"))
        b["property_id"] = str(b["property_id"])  # stringify
        b["user_id"] = str(b["user_id"])  # stringify
        res.append(b)
    return res


@app.get("/host/bookings")
async def host_bookings(user=Depends(get_current_user)):
    if user.get("role") not in ["host", "admin"]:
        raise HTTPException(status_code=403, detail="صلاحيات غير كافية")
    # bookings for properties owned by host
    prop_ids = [p["_id"] for p in db["property"].find({"host_id": user["id"]}, {"_id": 1})]
    cur = db["booking"].find({"property_id": {"$in": prop_ids}})
    res = []
    for b in cur:
        b["id"] = str(b.pop("_id"))
        b["property_id"] = str(b["property_id"])  # stringify
        b["user_id"] = str(b["user_id"])  # stringify
        res.append(b)
    return res


# Admin
@app.get("/admin/stats")
async def admin_stats(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="صلاحيات المسؤول مطلوبة")
    users = db["user"].count_documents({})
    hosts = db["user"].count_documents({"role": "host"})
    properties = db["property"].count_documents({})
    bookings = db["booking"].count_documents({})
    return {"users": users, "hosts": hosts, "properties": properties, "bookings": bookings}


@app.get("/admin/users")
async def admin_users(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="صلاحيات المسؤول مطلوبة")
    cur = db["user"].find({})
    res = []
    for u in cur:
        res.append(user_safe(u))
    return res


@app.delete("/admin/properties/{prop_id}")
async def admin_delete_property(prop_id: str, user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="صلاحيات المسؤول مطلوبة")
    db["property"].delete_one({"_id": to_object_id(prop_id)})
    return {"deleted": True}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
