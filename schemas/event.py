from pydantic import BaseModel
from typing import Optional, List
from datetime import date
from uuid import UUID
from .attribute import AttributeMinimal

class EventMinimalBase(BaseModel):
    info: str
    uuid: UUID
    attribute_count: Optional[int] = None
    threat_level_id: Optional[int] = None
    date: Optional[date]

class EventMinimalCreate(EventMinimalBase):
    pass

class EventMinimal(EventMinimalBase):
    id: int
    attributes: List[AttributeMinimal] = []

    class Config:
        from_attributes = True
