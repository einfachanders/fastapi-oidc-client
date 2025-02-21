# 3rd party imports
from fastapi import APIRouter

router = APIRouter(
    prefix="/health",
    tags=["health"]
)

@router.get(f"")
async def health():
    return {"status": "online"}
