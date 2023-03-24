from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Boolean

Base = declarative_base()

class Subscriber(Base):
    __tablename__ = "subscribers"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String)
    user_name = Column(String)
    is_gifted = Column(Boolean)
    profile_photo = Column(String)
    founder       = Column(String, default="no")