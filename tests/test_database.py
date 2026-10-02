import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base, PredictionRecord
from database.repository import PredictionRepository

# In-memory SQLite for test isolation
TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


def test_create_prediction_record(db_session):
    record = PredictionRepository.create_record(
        db=db_session,
        url="https://paypal-update.online/auth",
        prediction="phishing",
        probability=0.92,
        risk_level="HIGH",
        model_version="v1.0.0"
    )

    assert record.id is not None
    assert record.url == "https://paypal-update.online/auth"
    assert record.prediction == "phishing"
    assert record.probability == 0.92
    assert record.risk_level == "HIGH"
    assert record.created_at is not None


def test_get_history_and_stats(db_session):
    # Add multiple records
    PredictionRepository.create_record(db_session, "https://google.com", "legitimate", 0.02, "LOW")
    PredictionRepository.create_record(db_session, "https://chase-login.xyz", "phishing", 0.88, "HIGH")
    PredictionRepository.create_record(db_session, "https://suspicious-site.tk", "phishing", 0.55, "MEDIUM")

    history = PredictionRepository.get_history(db_session, limit=10)
    assert len(history) == 3

    stats = PredictionRepository.get_stats(db_session)
    assert stats["total_scans"] == 3
    assert stats["phishing_detected"] == 2
    assert stats["legitimate_detected"] == 1
    assert stats["risk_distribution"]["LOW"] == 1
    assert stats["risk_distribution"]["MEDIUM"] == 1
    assert stats["risk_distribution"]["HIGH"] == 1
