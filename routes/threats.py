from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload
from db import get_db
from models.attribute import AttributeMinimal
from schemas.attribute import AttributeMinimalBase
from models.event import EventMinimal
from schemas.event import EventMinimalBase # Ensure this import is correct
from routes.auth import get_current_user, User
from typing import List
from sqlalchemy import func, or_
from pydantic import BaseModel

router = APIRouter(
    prefix="/threats",
    tags=["Threats"]
)

class AttrCount(BaseModel):
    event: str
    count: int

class EventCategory(BaseModel):
    category: str
    count: int

@router.get("/attr_count", response_model=List[AttrCount])
async def get_attr_counts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    results = (
        db.query(EventMinimal.info, func.sum(EventMinimal.attribute_count).label("count"))
        .filter(EventMinimal.info.isnot(None))
        .group_by(EventMinimal.info)
        .order_by(func.sum(EventMinimal.attribute_count).desc())
        .all()
    )
    return [{"event": r[0], "count": r[1]} for r in results]

@router.get("/event_categories", response_model=List[EventCategory])
async def get_event_categories(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get count of attributes grouped by category"""
    results = (
        db.query(AttributeMinimal.category, func.count(AttributeMinimal.id).label("count"))
        .filter(AttributeMinimal.category.isnot(None))
        .group_by(AttributeMinimal.category)
        .order_by(func.count(AttributeMinimal.id).desc())
        .all()
    )
    return [{"category": r[0], "count": r[1]} for r in results]

@router.get("/ips", response_model=List[str])
async def get_threat_ips(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    ips = db.query(AttributeMinimal.value).filter(AttributeMinimal.type.ilike("%ip%")).all()
    return [ip[0] for ip in ips]

@router.get("/domains", response_model=List[str])
async def get_threat_domains(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    domains = db.query(AttributeMinimal.value).filter(AttributeMinimal.type.ilike("%domain%")).all()
    return [domain[0] for domain in domains]

@router.get("/hashes", response_model=List[str])
async def get_threat_hashes(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    hashes = (
        db.query(AttributeMinimal.value)
        .filter(
            (AttributeMinimal.type.ilike("%sha%")) |
            (AttributeMinimal.type.ilike("%md%"))
        )
        .all()
    )
    return [h[0] for h in hashes]

@router.get("/urls", response_model=List[str])
async def get_threat_urls(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    urls = db.query(AttributeMinimal.value).filter(AttributeMinimal.type.ilike("%url%")).all()
    return [url[0] for url in urls]

@router.get("/emails", response_model=List[str])
async def get_threat_emails(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    emails = db.query(AttributeMinimal.value).filter(AttributeMinimal.type.ilike("%email%")).all()
    return [email[0] for email in emails]

@router.get("/regkeys", response_model=List[str])
async def get_threat_regkeys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    regkeys = db.query(AttributeMinimal.value).filter(AttributeMinimal.type.ilike("%regkey%")).all()
    return [regkey[0] for regkey in regkeys]

@router.get("/ip_count")
async def ip_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    ip_count = db.query(AttributeMinimal).filter(AttributeMinimal.type.ilike("%ip%")).count()
    return {"ip_count": ip_count}

@router.get("/domain_count")
async def domain_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    domain_count = db.query(AttributeMinimal).filter(AttributeMinimal.type.ilike("%domain%")).count()
    return {"domain_count": domain_count}

@router.get("/url_count")
async def url_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    url_count = db.query(AttributeMinimal).filter(AttributeMinimal.type.ilike("%url%")).count()
    return {"url_count": url_count}

@router.get("/hash_count")
async def hash_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    hash_count = db.query(AttributeMinimal).filter(
    or_(
        AttributeMinimal.type.ilike("%sha%"),
        AttributeMinimal.type.ilike("%md%")
    )
).count()
    return {"hash_count": hash_count}

@router.get("/email_count")
async def email_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    email_count = db.query(AttributeMinimal).filter(AttributeMinimal.type.ilike("%email%")).count()
    return {"email_count": email_count}

@router.get("/regkey_count")
async def regkey_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    regkey_count = db.query(AttributeMinimal).filter(AttributeMinimal.type.ilike("%regkey%")).count()
    return {"regkey_count": regkey_count}

@router.get("/attribute/{value}", response_model=List[AttributeMinimalBase])
async def get_attribute_by_value(
    value: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # This query already uses joinedload to fetch the associated event data
    attributes = (
        db.query(AttributeMinimal)
        .options(joinedload(AttributeMinimal.event))
        .filter(AttributeMinimal.value == value)
        .all()
    )
    if not attributes:
        raise HTTPException(status_code=404, detail=f"Attribute with value '{value}' not found")

    return attributes 