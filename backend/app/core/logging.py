import http
import logging
import logging.config
import os
import yaml
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings


# with open(os.path.join(settings.PROJECT_DIR, "core", "logging.yaml"), "rt", encoding="us-ascii") as f:
#     config = yaml.safe_load(f.read())
# logging.config.dictConfig(config)


def _get_status_line(status_code: int) -> str:
    try:
        phrase = http.HTTPStatus(status_code).phrase
    except ValueError:
        phrase = ""
    return "".join([str(status_code), " ", phrase])


STATUS_LINE = {status_code: _get_status_line(status_code) for status_code in range(100, 600)}


def get_logger(name: str) -> logging.Logger:
    """Creates a standard logger."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    return logger


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log requests and responses."""
    def __init__(self, app: FastAPI, logger: logging.Logger):
        super().__init__(app)
        self.logger = logger

    async def dispatch(self, request: Request, call_next):
        self.logger.info(f"Request received: {request.method} {request.url.path}" + 
                         (("?" + request.url.query) if request.url.query else ""))

        response = await call_next(request)
        
        self.logger.info(f"Response sent: {STATUS_LINE[response.status_code]}")
        
        return response

# disable uvicorn logging
uvicorn_access = get_logger("uvicorn.access").disabled = True
uvicorn_error = get_logger("uvicorn.error").disabled = True
