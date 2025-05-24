from pydantic import BaseModel
from typing import Optional

class AttributeMinimalBase(BaseModel):
    category: str
    uuid: str
    type: str
    value: str
    to_ids: bool
    created_ts: int

class AttributeMinimalCreate(AttributeMinimalBase):
    pass

class AttributeMinimal(AttributeMinimalBase):
    id: int

    class Config:
        from_attributes = True
