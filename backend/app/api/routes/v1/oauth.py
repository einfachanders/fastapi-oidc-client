from fastapi import APIRouter, Response
from fastapi.responses import RedirectResponse
from app.core.config import settings

router = APIRouter(
    prefix="/oauth",
    tags=["oauth"]
)


@router.get("")
def init_oauth(response: Response) -> RedirectResponse:
    response.set_cookie(
        key="auth_session",
        value="test",
        max_age=120,
        path="/",
        domain=settings.FASTAPI_DOMAIN,
        secure=True if settings.FASTAPI_PROTOCOL == "https" else False,
        httponly=True,
        samesite="lax"
    )
    return


@router.get("/callback")
def oauth_callback(response: Response) -> None:
    response.delete_cookie("auth_session")
    return
