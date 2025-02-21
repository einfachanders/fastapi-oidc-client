# 3rd party imports
from fastapi import APIRouter
# local modules
from app.api.routes import health
from app.api.routes.v1 import auth, oauth

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router, prefix="/v1")
api_router.include_router(oauth.router, prefix="/v1")