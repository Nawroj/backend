from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, BigInteger
from sqlalchemy.orm import relationship
from db import Base

class AttributeMinimal(Base):
    __tablename__ = "attributes_minimal"

    id = Column(Integer, primary_key=True, index=True)
    category = Column(String, nullable=False)
    event_info = Column(String, ForeignKey("events_minimal.info"))
    type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    to_ids = Column(Boolean, default=False)
    created_ts = Column(String)
    country_code = Column(String)


    # Relationship to event
    event = relationship("EventMinimal", back_populates="attributes")
