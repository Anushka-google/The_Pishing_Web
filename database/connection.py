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


_db_initialized = False


def init_db(max_retries: int = 5, retry_delay: float = 2.0):
    """Initializes tables in database with retry resilience for container startup."""
    global _db_initialized
    import time
    for attempt in range(1, max_retries + 1):
        try:
            Base.metadata.create_all(bind=engine)
            from sqlalchemy import inspect, text
            inspector = inspect(engine)
            if "prediction" in inspector.get_table_names():
                existing_cols = {col["name"] for col in inspector.get_columns("prediction")}
                needed_cols = [
                    ("feature_extraction_ms", "FLOAT"),
                    ("model_inference_ms", "FLOAT"),
                    ("db_latency_ms", "FLOAT"),
                    ("api_response_time_ms", "FLOAT"),
                    ("bottleneck", "VARCHAR(32)")
                ]
                with engine.connect() as conn:
                    for col_name, col_type in needed_cols:
                        if col_name not in existing_cols:
                            conn.execute(text(f"ALTER TABLE prediction ADD COLUMN {col_name} {col_type}"))
                    conn.commit()
            _db_initialized = True
            return
        except Exception:
            if attempt < max_retries:
                time.sleep(retry_delay)
            else:
                pass


def get_db():
    """FastAPI Dependency for database session lifecycle management."""
    global _db_initialized
    if not _db_initialized:
        init_db()
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Ensure SQLite tables exist upon module import
if DATABASE_URL.startswith("sqlite"):
    try:
        init_db()
    except Exception:
        pass
