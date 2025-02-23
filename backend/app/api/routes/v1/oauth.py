import json
from typing import Annotated
from fastapi import APIRouter, Query, Request, Response, HTTPException, Form
from fastapi.responses import RedirectResponse
from app.core.config import settings
from app.deps import session_store
from app.schemas.api_responses import CallbackResponse, RefreshResponse
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


@router.get("/callback", status_code=200, response_model=CallbackResponse)
async def oauth_callback(auth_response: Annotated[AuthorizationResponse, Query()], 
                         request: Request, response: Response) -> CallbackResponse:
    # get oauth session data from cookie (nonce, oauth_state, code_verifier)
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

    # request tokens from OpenID Provider/OAuth Authorization Server
    token_resp = await oidc.autorize(
        code=auth_response.code,
        code_verifier=oauth_session["code_verifier"]
    )

    # verify retrieved access and id token
    verified_access_token = await oidc.verify_token_resp(token_resp, oauth_session)
    
    # directly add this session to the session store since it was just created
    await session_store.update_session(verified_access_token.sid, verified_access_token.sub,
                                 verified_access_token.exp)

    response.delete_cookie("oauth_session")
    return CallbackResponse(**token_resp)


@router.post("/refresh", status_code=200, response_model=RefreshResponse)
async def refresh_token(grant_type: Annotated[str, Form()], refresh_token: Annotated[str, Form()]):
    # use user agents refresh_token to refresh access, id and refresh_token
    token_resp = await oidc.refresh(refresh_token)

    # verify retrieved access token
    # TODO: check if it is possible to verify the id token although no new nonce was provided
    verified_access_token = await oidc.verify_access_token(token_resp["access_token"])

    # update session in session store
    await session_store.update_session(verified_access_token.sid, verified_access_token.sub,
                                       verified_access_token.exp)

    return RefreshResponse(**token_resp)


# TODO: User logout endpoint and backchannel logout endpoint
