"""
Phishing Detection & Risk Intelligence Platform
FastAPI Application Entrypoint

Exposes RESTful endpoints for real-time URL risk analysis,
threat explanation, scan logging, and telemetry metrics.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from api.routes import router, get_predictor
from database.connection import init_db
from api.middleware import StructuredLoggingMiddleware
from api.logging_config import logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables
    logger.info("Initializing Database schema (PostgreSQL / SQLite)...")
    try:
        init_db()
    except Exception as e:
        logger.warning(f"Database schema initialization deferred: {e}")

    # Pre-warm model and SHAP explainer on startup
    logger.info("Pre-warming Phishing Detection Engine & SHAP TreeExplainer...")
    try:
        predictor = get_predictor()
        # Execute a lightweight dummy prediction to trigger JIT / cache compilation
        predictor.predict("https://www.example.com", include_explanation=False)
        logger.info(f"Engine pre-warmed successfully. Ready for inference with {predictor.model_name} ({predictor.model_version}).")
    except Exception as e:
        logger.warning(f"Engine pre-warm warning: {e}")
    yield


app = FastAPI(
    title="Phishing Detection & Risk Intelligence API",
    description=(
        "Production-grade cybersecurity intelligence service. Inspects URLs, "
        "extracts 22 RFC/entropy features, computes calibrated threat probabilities, "
        "and provides SHAP-based explainability."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Phase 24: Structured JSON request logging & X-Request-ID correlation
app.add_middleware(StructuredLoggingMiddleware)

# Enable CORS for React Frontend & browser extensions
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins in dev; restrict in prod env
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom validation error handler for friendly error messages
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for err in exc.errors():
        msg = err.get("msg", "Invalid parameter")
        # Strip internal pydantic prefixes if present
        if msg.startswith("Value error, "):
            msg = msg.replace("Value error, ", "")
        errors.append({
            "loc": err.get("loc"),
            "message": msg,
            "type": err.get("type")
        })

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "URL Validation Error",
            "details": errors
        }
    )


# Register API routes
app.include_router(router, prefix="/api/v1")
app.include_router(router)  # Also expose directly at root /health, /predict, etc.


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
