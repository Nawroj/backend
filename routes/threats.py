from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, or_
from db import get_db
from models.attribute import AttributeMinimal
from schemas.attribute import AttributeMinimalBase
from models.event import EventMinimal
# from schemas.event import EventMinimalBase # User's original comment: Ensure this import is correct or remove if not used
from routes.auth import get_current_user, User
from typing import List, Optional
from pydantic import BaseModel

router = APIRouter(
    prefix="/threats",
    tags=["Threats"]
)

# --- Pydantic Models ---
class AttrCount(BaseModel):
    event: str
    count: int

class EventCategory(BaseModel):
    category: str
    count: int

class AttributeDetailResponse(BaseModel):
    value: str
    event_info: Optional[str]

# --- Helper Functions ---
def apply_iso_string_time_filter(query, column_to_filter, start_date_str: str = None, end_date_str: str = None):
    """
    Applies time filtering to a query based on a column storing ISO 8601 date strings.
    `column_to_filter` is the SQLAlchemy model attribute (e.g., AttributeMinimal.created_ts or EventMinimal.date).
    Assumes start_date_str and end_date_str are valid ISO 8601 strings if provided.
    """
    if start_date_str:
        query = query.filter(column_to_filter >= start_date_str)
    
    if end_date_str:
        query = query.filter(column_to_filter <= end_date_str)
    return query

# --- API Endpoints ---
@router.get("/attr_count", response_model=List[AttrCount])
async def get_attr_counts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None, # Parameter is accepted but will not be used for filtering
    end_date_str: str = None  # Parameter is accepted but will not be used for filtering
):
    # This endpoint is NOT date filtered as per user request for the specific chart
    query = (
        db.query(EventMinimal.info, func.sum(EventMinimal.attribute_count).label("count"))
        .filter(EventMinimal.info.isnot(None))
    )
    results = (
        query.group_by(EventMinimal.info)
        .order_by(func.sum(EventMinimal.attribute_count).desc())
        .all()
    )
    return [{"event": r[0], "count": r[1]} for r in results]

@router.get("/event_categories", response_model=List[EventCategory])
async def get_event_categories(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None,
    end_date_str: str = None
):
    query = (
        db.query(AttributeMinimal.category, func.count(AttributeMinimal.id).label("count"))
        .filter(AttributeMinimal.category.isnot(None))
    )
    query = apply_iso_string_time_filter(query, AttributeMinimal.created_ts, start_date_str, end_date_str)
    results = (
        query.group_by(AttributeMinimal.category)
        .order_by(func.count(AttributeMinimal.id).desc())
        .all()
    )
    return [{"category": r[0], "count": r[1]} for r in results]

@router.get("/ips", response_model=List[AttributeDetailResponse])
async def get_threat_ips(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None,
    end_date_str: str = None
):
    query = db.query(AttributeMinimal.value, AttributeMinimal.event_info).filter(AttributeMinimal.type.ilike("%ip%"))
    query = apply_iso_string_time_filter(query, AttributeMinimal.created_ts, start_date_str, end_date_str)
    results = query.all()
    return [{"value": value, "event_info": event_info} for value, event_info in results]

@router.get("/domains", response_model=List[AttributeDetailResponse])
async def get_threat_domains(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None,
    end_date_str: str = None
):
    query = db.query(AttributeMinimal.value, AttributeMinimal.event_info).filter(AttributeMinimal.type.ilike("%domain%"))
    query = apply_iso_string_time_filter(query, AttributeMinimal.created_ts, start_date_str, end_date_str)
    results = query.all()
    return [{"value": value, "event_info": event_info} for value, event_info in results]

@router.get("/hashes", response_model=List[AttributeDetailResponse])
async def get_threat_hashes(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None,
    end_date_str: str = None
):
    query = (
        db.query(AttributeMinimal.value, AttributeMinimal.event_info)
        .filter(
            (AttributeMinimal.type.ilike("%sha%")) |
            (AttributeMinimal.type.ilike("%md%"))
        )
    )
    query = apply_iso_string_time_filter(query, AttributeMinimal.created_ts, start_date_str, end_date_str)
    results = query.all()
    return [{"value": value, "event_info": event_info} for value, event_info in results]

@router.get("/urls", response_model=List[AttributeDetailResponse])
async def get_threat_urls(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None,
    end_date_str: str = None
):
    query = db.query(AttributeMinimal.value, AttributeMinimal.event_info).filter(AttributeMinimal.type.ilike("%url%"))
    query = apply_iso_string_time_filter(query, AttributeMinimal.created_ts, start_date_str, end_date_str)
    results = query.all()
    return [{"value": value, "event_info": event_info} for value, event_info in results]

@router.get("/emails", response_model=List[AttributeDetailResponse])
async def get_threat_emails(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None,
    end_date_str: str = None
):
    query = db.query(AttributeMinimal.value, AttributeMinimal.event_info).filter(AttributeMinimal.type.ilike("%email%"))
    query = apply_iso_string_time_filter(query, AttributeMinimal.created_ts, start_date_str, end_date_str)
    results = query.all()
    return [{"value": value, "event_info": event_info} for value, event_info in results]

@router.get("/regkeys", response_model=List[AttributeDetailResponse])
async def get_threat_regkeys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None,
    end_date_str: str = None
):
    query = db.query(AttributeMinimal.value, AttributeMinimal.event_info).filter(AttributeMinimal.type.ilike("%regkey%"))
    query = apply_iso_string_time_filter(query, AttributeMinimal.created_ts, start_date_str, end_date_str)
    results = query.all()
    return [{"value": value, "event_info": event_info} for value, event_info in results]

@router.get("/ip_count")
async def ip_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None,
    end_date_str: str = None
):
    query = db.query(AttributeMinimal).filter(AttributeMinimal.type.ilike("%ip%"))
    query = apply_iso_string_time_filter(query, AttributeMinimal.created_ts, start_date_str, end_date_str)
    count = query.count()
    return {"ip_count": count}

@router.get("/domain_count")
async def domain_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None,
    end_date_str: str = None
):
    query = db.query(AttributeMinimal).filter(AttributeMinimal.type.ilike("%domain%"))
    query = apply_iso_string_time_filter(query, AttributeMinimal.created_ts, start_date_str, end_date_str)
    count = query.count()
    return {"domain_count": count}

@router.get("/url_count")
async def url_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None,
    end_date_str: str = None
):
    query = db.query(AttributeMinimal).filter(AttributeMinimal.type.ilike("%url%"))
    query = apply_iso_string_time_filter(query, AttributeMinimal.created_ts, start_date_str, end_date_str)
    count = query.count()
    return {"url_count": count}

@router.get("/hash_count")
async def hash_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None,
    end_date_str: str = None
):
    query = db.query(AttributeMinimal).filter(
        or_(
            AttributeMinimal.type.ilike("%sha%"),
            AttributeMinimal.type.ilike("%md%")
        )
    )
    query = apply_iso_string_time_filter(query, AttributeMinimal.created_ts, start_date_str, end_date_str)
    count = query.count()
    return {"hash_count": count}

@router.get("/email_count")
async def email_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None,
    end_date_str: str = None
):
    query = db.query(AttributeMinimal).filter(AttributeMinimal.type.ilike("%email%"))
    query = apply_iso_string_time_filter(query, AttributeMinimal.created_ts, start_date_str, end_date_str)
    count = query.count()
    return {"email_count": count}

@router.get("/regkey_count")
async def regkey_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None,
    end_date_str: str = None
):
    query = db.query(AttributeMinimal).filter(AttributeMinimal.type.ilike("%regkey%"))
    query = apply_iso_string_time_filter(query, AttributeMinimal.created_ts, start_date_str, end_date_str)
    count = query.count()
    return {"regkey_count": count}

@router.get("/attribute/{value}", response_model=List[AttributeMinimalBase])
async def get_attribute_by_value(
    value: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date_str: str = None,
    end_date_str: str = None
):
    query = (
        db.query(AttributeMinimal)
        .options(joinedload(AttributeMinimal.event))
        .filter(AttributeMinimal.value == value)
    )
    query = apply_iso_string_time_filter(query, AttributeMinimal.created_ts, start_date_str, end_date_str)
    
    attributes = query.all()
    
    if not attributes:
        detail_msg = f"Attribute with value '{value}' not found"
        if start_date_str or end_date_str:
            detail_msg += " within the specified date range"
        raise HTTPException(status_code=404, detail=detail_msg)

    return attributes

@router.get("/events-by-threat/{level_id}")
async def get_events_by_threat_level(
    level_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from models.event import EventMinimal
    events = (
        db.query(EventMinimal.info)
        .filter(EventMinimal.threat_level_id == level_id)
        .all()
    )
    return [e[0] for e in events if e[0]]

@router.get("/threat-level-stats")
async def get_threat_level_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from models.event import EventMinimal
    from sqlalchemy import func

    results = (
        db.query(EventMinimal.threat_level_id, func.count().label("event_count"))
        .group_by(EventMinimal.threat_level_id)
        .order_by(EventMinimal.threat_level_id)
        .all()
    )

    return {str(level): count for level, count in results}
