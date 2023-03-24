from pydantic import BaseModel
from typing import Optional


class SubscriberBase(BaseModel):
    user_id: str
    user_name: str
    is_gifted: bool


class SubscriberCreate(SubscriberBase):
    pass


class SubscriberUpdate(SubscriberCreate):
    pass


class SubscriberInDB(SubscriberCreate):
    id: int
    user_id: str
    user_name: str
    is_gifted: bool

    class Config:
        orm_mode = True
