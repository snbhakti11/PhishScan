# db.py
"""
Database module using SQLAlchemy (SQLite).
Provides simple interface to store and fetch scan results.
"""

import os
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

from sqlalchemy import create_engine, Column, Integer, Text, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base

DB_FILE = os.getenv("PHISHSCAN_DB", "phishscan.db")
DATABASE_URL = f"sqlite:///{DB_FILE}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(Text, index=True)
    normalized_url = Column(Text, index=True)
    verdict = Column(Text)
    score = Column(Integer)
    result_json = Column(Text)  # store full JSON as text
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def save_scan(url: str, normalized_url: str, verdict: str, score: int, result: Dict[str, Any]) -> int:
    session = SessionLocal()
    scan = Scan(
        url=url,
        normalized_url=normalized_url,
        verdict=verdict,
        score=score,
        result_json=json.dumps(result),
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    scan_id = scan.id
    session.close()
    return scan_id


def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    session = SessionLocal()
    scan = session.query(Scan).filter(Scan.id == scan_id).first()
    session.close()
    if not scan:
        return None
    return {
        "id": scan.id,
        "url": scan.url,
        "normalized_url": scan.normalized_url,
        "verdict": scan.verdict,
        "score": scan.score,
        "result": json.loads(scan.result_json),
        "created_at": scan.created_at.isoformat(),
    }


def list_scans(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    session = SessionLocal()
    rows = session.query(Scan).order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
    session.close()
    result = []
    for r in rows:
        result.append({
            "id": r.id,
            "url": r.url,
            "normalized_url": r.normalized_url,
            "verdict": r.verdict,
            "score": r.score,
            "created_at": r.created_at.isoformat(),
        })
    return result
