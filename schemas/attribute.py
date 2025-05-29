from pydantic import BaseModel
from typing import Optional
from uuid import UUID
from datetime import datetime

class AttributeMinimalBase(BaseModel):
    category: str
    uuid: UUID
    type: str
    value: str
    to_ids: bool
    created_ts: datetime

class AttributeMinimalCreate(AttributeMinimalBase):
    pass

class AttributeMinimal(AttributeMinimalBase):
    id: int

    class Config:
        from_attributes = True
