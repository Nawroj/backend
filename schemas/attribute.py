from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from .event import EventMinimalBase

class AttributeMinimalBase(BaseModel):
    # Pydantic schema for the AttributeMinimal model, including nested Event data
    id: int
    category: str
    event_info: str # Change to UUID type to match SQLAlchemy's return
    type: str
    value: str
    to_ids: bool
    created_ts: Optional[datetime] # Change to datetime type to match SQLAlchemy's return
    event: Optional[EventMinimalBase]
    

class AttributeMinimalCreate(AttributeMinimalBase):
    pass

class AttributeMinimal(AttributeMinimalBase):
    id: int

    class Config:
        from_attributes = True
