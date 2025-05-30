from sqlalchemy import Column, Integer, String, ForeignKey, Date
from sqlalchemy.orm import relationship
from db import Base

class EventMinimal(Base):
    __tablename__ = "events_minimal"

    id = Column(Integer, primary_key=True, index=True)
    info = Column(String, nullable=False)
    attribute_count = Column(Integer)
    threat_level_id = Column(Integer)
    date = Column(Date)

    # Relationship to attributes
    attributes = relationship("AttributeMinimal", back_populates="event")
