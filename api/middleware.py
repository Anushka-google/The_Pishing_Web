"""
Phishing Detection & Risk Intelligence Platform
Phase 24: Structured Logging Middleware for FastAPI

Captures HTTP request/response metrics and emits structured JSON logs with:
- timestamp
- request_id (correlated with X-Request-ID header)
- endpoint
- model_version
- prediction_latency
- prediction_result
- HTTP status code and total roundtrip duration
"""

import time
import uuid
from typing import Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from api.logging_config import logger


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        t0 = time.perf_counter()

        # 1. Correlate or generate unique request_id
        incoming_req_id = request.headers.get("x-request-id") or request.headers.get("X-Request-ID")
        request_id = incoming_req_id if incoming_req_id else f"req_{uuid.uuid4().hex[:12]}"
        request.state.request_id = request_id

        # 2. Forward request through application pipeline
        response = None
        exception_caught = None
        try:
            response = await call_next(request)
        except Exception as exc:
            exception_caught = exc
            raise exc
        finally:
            total_duration_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            status_code = response.status_code if response else 500

            # 3. Extract operational metadata from route state
            endpoint = f"{request.method} {request.url.path}"
            model_version = getattr(request.state, "model_version", None)
            prediction_latency = getattr(request.state, "prediction_latency", None)
            prediction_result = getattr(request.state, "prediction_result", None)
            sanitized_url = getattr(request.state, "sanitized_url", None)
            client_ip = request.client.host if request.client else "unknown"

            # 4. Construct log extra fields
            extra = {
                "request_id": request_id,
                "endpoint": endpoint,
                "status_code": status_code,
                "total_latency_ms": total_duration_ms,
                "client_ip": client_ip
            }
            if model_version is not None:
                extra["model_version"] = model_version
            if prediction_latency is not None:
                extra["prediction_latency"] = prediction_latency
            if prediction_result is not None:
                extra["prediction_result"] = prediction_result
            if sanitized_url is not None:
                extra["sanitized_url"] = sanitized_url

            # 5. Emit structured JSON log
            log_level = logger.error if (status_code >= 500 or exception_caught) else (logger.warning if status_code >= 400 else logger.info)
            log_level(
                f"{endpoint} completed with status {status_code} in {total_duration_ms}ms",
                extra=extra
            )

        # 6. Inject X-Request-ID into response headers for client tracing
        if response is not None:
            response.headers["X-Request-ID"] = request_id

        return response
