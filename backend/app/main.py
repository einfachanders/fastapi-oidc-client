from app.core import logging

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from app.api.main import api_router
from app.core.config import settings

from app.security import oidc

# init FastAPI application
app = FastAPI(
    title=settings.FASTAPI_PROJECT_NAME,
    openapi_url=f"{settings.FASTAPI_BASE_URI}/openapi.json",
    docs_url=f"{settings.FASTAPI_BASE_URI}/docs"
)

# Set all CORS enabled origins
if settings.FASTAPI_BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            str(origin).strip("/") for origin in settings.FASTAPI_BACKEND_CORS_ORIGINS
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

logger = logging.get_logger(__name__)

app.add_middleware(logging.LoggingMiddleware, logger=logger)

app.include_router(
    api_router,
    prefix=settings.FASTAPI_BASE_URI
)

logger.info(f"{settings.FASTAPI_PROJECT_NAME} ready and accepting connection")
