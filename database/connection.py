"""
Phishing Detection & Risk Intelligence Platform
Phase 17: Database Connection & Session Management

Provides dual support for PostgreSQL (production/docker) and SQLite (local dev),
enabling out-of-the-box local execution without external service dependencies.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from database.models import Base

# Database URL from environment or default local SQLite database
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./data/phishing_intelligence.db"
)

# Connect args (needed for SQLite multi-threading)
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

# Ensure data directory exists if using SQLite
if DATABASE_URL.startswith("sqlite"):
    db_file_path = DATABASE_URL.replace("sqlite:///", "")
    os.makedirs(os.path.dirname(os.path.abspath(db_file_path)), exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initializes tables in database if they do not exist."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI Dependency for database session lifecycle management."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
