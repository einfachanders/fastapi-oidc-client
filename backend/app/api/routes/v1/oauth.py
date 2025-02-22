from typing import Annotated

from fastapi import APIRouter, Query, Request, Response, HTTPException
from fastapi.responses import RedirectResponse
from app.core.config import settings
from app.schemas.oidc import AuthorizationResponse
from app.security import oidc

router = APIRouter(
    prefix="/oauth",
    tags=["oauth"]
)


@router.get("")
async def init_oauth(response: Response) -> RedirectResponse:
    # Generate PKCE code verifier and code challenge
    # https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
    code_verifier, code_challenge = await oidc.gen_oauth_code_challenge()
    oidc_nonce = await oidc.gen_oidc_nonce()
    oauth_state = await oidc.gen_oauth_state()

    oauth_session_jws = await oidc.gen_auth_jws(
        code_verifier=code_verifier,
        oidc_nonce=oidc_nonce,
        oauth_state=oauth_state
    )
    
    oidc_redirect_url = await oidc.gen_oidc_auth_req_url(
        code_challenge=code_challenge,
        oidc_nonce=oidc_nonce,
        oauth_state=oauth_state
    )

    response = RedirectResponse(
        url=oidc_redirect_url
    )

    response.set_cookie(
        key="oauth_session",
        value=oauth_session_jws,
        max_age=120,
        path="/",
        domain=settings.FASTAPI_DOMAIN,
        secure=True if settings.FASTAPI_PROTOCOL == "https" else False,
        httponly=True,
        samesite="lax"
    )
    return response


@router.get("/callback")
async def oauth_callback(auth_response: Annotated[AuthorizationResponse, Query()], 
                         request: Request, response: Response) -> None:
    oauth_session_cookie = request.cookies["oauth_session"]
    oauth_session = await oidc.verify_auth_jws(oauth_session_cookie)

    # verify oauth state
    if not oauth_session["oauth_state"] == auth_response.state:
        raise HTTPException(
            status_code=400,
            detail={
                "status_code": 400,
                "status_message": "Bad Request",
                "error": "Invalid OAuth state"
            }
        )

    # verify issuer
    if not auth_response.iss == settings.KEYCLOAK_ISSUER:
        raise HTTPException(
            status_code=400,
            detail={
                "status_code": 400,
                "status_message": "Bad Request",
                "error": "Unexpected issuer"
            }
        )

    # request tokens
    token_resp = await oidc.autorize(
        code=auth_response.code,
        code_verifier=oauth_session["code_verifier"]
    )

    await oidc.verify_token_resp(token_resp, oauth_session)

    response.delete_cookie("auth_session")
    return
