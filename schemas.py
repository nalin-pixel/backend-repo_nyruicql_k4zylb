"""
Database Schemas for Saknli (سكنلي)

Each Pydantic model maps to a MongoDB collection with the lowercase class name.
"""
from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr
from datetime import date, datetime

# Users
class User(BaseModel):
    full_name: str = Field(..., description="الاسم الكامل")
    email: EmailStr = Field(..., description="البريد الإلكتروني")
    password_hash: str = Field(..., description="هاش كلمة المرور")
    role: str = Field("user", description="الدور: user | host | admin")
    phone: Optional[str] = Field(None, description="رقم الهاتف")
    city: Optional[str] = Field(None, description="المدينة في تركيا")

# Sessions (tokens)
class Session(BaseModel):
    user_id: str
    token: str
    expires_at: datetime

# Property (Listing)
class Property(BaseModel):
    title: str = Field(..., description="العنوان بالعربية")
    description: str = Field(..., description="الوصف")
    city: str = Field(..., description="المدينة")
    address: str = Field(..., description="العنوان التفصيلي")
    type: str = Field(..., description="النوع: غرفة / شقة / سكن طلاب")
    price_per_month: float = Field(..., ge=0, description="السعر بالشهر بالليرة")
    images: List[str] = Field(default_factory=list, description="روابط الصور")
    lat: Optional[float] = Field(None, description="خط العرض")
    lng: Optional[float] = Field(None, description="خط الطول")
    distance_to_university: Optional[str] = Field(None, description="المسافة إلى الجامعة")
    available_from: Optional[date] = Field(None)
    available_to: Optional[date] = Field(None)
    host_id: str = Field(..., description="معرف المالك")
    is_active: bool = Field(True)

# Booking
class Booking(BaseModel):
    property_id: str
    user_id: str
    start_date: date
    end_date: date
    guests: int = Field(1, ge=1, le=10)
    status: str = Field("pending", description="pending | confirmed | rejected | cancelled")

