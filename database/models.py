"""
Phishing Detection & Risk Intelligence Platform
Phase 17: Database Models (SQLAlchemy ORM)

Clean, lightweight relational schema for logging URL risk assessments:
prediction
-----------------------
id            : Integer (Primary Key)
url           : String(2048)
prediction    : String(32)    ('phishing' | 'legitimate')
probability   : Float         (0.00 to 1.00)
risk_level    : String(16)    ('LOW' | 'MEDIUM' | 'HIGH')
created_at    : DateTime      (UTC timestamp)
model_version : String(32)    ('v1.0.0')
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class PredictionRecord(Base):
    __tablename__ = "prediction"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    prediction = Column(String(32), nullable=False)
    probability = Column(Float, nullable=False)
    risk_level = Column(String(16), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    model_version = Column(String(32), default="v1.0.0", nullable=False)

    def to_dict(self):
        return {
            "id": str(self.id),
            "url": self.url,
            "prediction": self.prediction,
            "probability": round(float(self.probability), 4),
            "risk_level": self.risk_level,
            "action": "ALLOW" if self.risk_level == "LOW" else ("CAUTION" if self.risk_level == "MEDIUM" else "BLOCK"),
            "created_at": self.created_at.isoformat() if self.created_at else datetime.now(timezone.utc).isoformat(),
            "model_version": self.model_version
        }
