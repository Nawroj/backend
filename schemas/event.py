from pydantic import BaseModel
from typing import Optional, List
from datetime import date
from uuid import UUID

class EventMinimalBase(BaseModel):
    # Pydantic schema for the EventMinimal model
    info: str
    attribute_count: int
    threat_level_id: int
    date: date

class EventMinimalCreate(EventMinimalBase):
    pass

class Config:
         from_attributes = True
