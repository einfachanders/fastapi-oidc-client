import logging
import logging.config
import os
import traceback
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings
from app.core.exceptions import STATUS_LINE

# with open(os.path.join(settings.PROJECT_DIR, "core", "logging.yaml"), "rt", encoding="us-ascii") as f:
#     config = yaml.safe_load(f.read())
# logging.config.dictConfig(config)


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

        try:
            response = await call_next(request)
            self.logger.info(f"Response sent: {response.status_code}")
            return response
        except Exception as error:
            error_trace = "".join(traceback.format_exception(type(error), error, error.__traceback__))
            self.logger.error(f"Error while processing the request: {error_trace}")
            
            # Return a proper error response instead of None
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal Server Error"}
            )


# disable uvicorn logging
uvicorn_access = get_logger("uvicorn.access").disabled = True
uvicorn_error = get_logger("uvicorn.error").disabled = True
