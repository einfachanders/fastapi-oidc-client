import os
import base64
import hashlib
import httpx
import json
from cachetools import TTLCache
from jose import jws
from fastapi import HTTPException
from app.core.config import settings

state_cache = TTLCache(maxsize=float('inf'), ttl=120)


async def gen_oidc_nonce(nonce_length: int = 16) -> str:
    nonce = os.urandom(nonce_length).hex()
    return nonce


async def gen_oauth_state(state_length: int = 16) -> str:
    """Generates an oauth state as per 
    https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1

    Args:
        state_length (int, optional): Length of the state in bytes. Defaults to 16.

    Returns:
        str: OAuth state as hex string
    """
    state = os.urandom(state_length).hex()
    return state


async def gen_oauth_code_challenge() -> tuple[str, str]:
    # generate code_verifier https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
    code_verifier = os.urandom(32)
    code_verifier_encoded = base64.urlsafe_b64encode(code_verifier)
    # make url safe (i.e. remove "=")
    code_verifier_encoded = code_verifier_encoded.decode().rstrip("=")
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier_encoded.encode()).digest()).decode().rstrip("=")
    return code_verifier_encoded, code_challenge


async def gen_auth_jws(code_verifier: str, oidc_nonce: str, oauth_state: str) -> str:
    oauth_session = {
        "oidc_nonce": oidc_nonce,
        "oauth_state": oauth_state,
        "code_verifier": code_verifier
    }

    oauth_session_jws = jws.sign(
        payload=oauth_session,
        key=settings.FASTAPI_JWS_SECRET,
        algorithm="HS256"
    )

    return oauth_session_jws


async def gen_oidc_redirect(code_challenge: str, oauth_state: str, oidc_nonce: str) -> str:
    oidc_query_params = {
        "client_id": settings.KEYCLOAK_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": settings.KEYCLOAK_LOGIN_REDIRECT_URL,
        "scope": "openid email profile",
        "state": oauth_state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": oidc_nonce
    }
    return f"{settings.KEYCLOAK_AUTH_URL}?{httpx.QueryParams(oidc_query_params)}"


async def verify_auth_jws(oauth_session_jws: str) -> str:
    oauth_session = jws.verify(
        token=oauth_session_jws,
        key=settings.FASTAPI_JWS_SECRET,
        algorithms="HS256"
    )
    return json.loads(oauth_session.decode())


async def autorize(code: str, code_verifier: str) -> None:
    access_token_req = {
        "client_id": settings.KEYCLOAK_CLIENT_ID,
        "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
        "code": code,
        "code_verifier": code_verifier,
        "grant_type": "authorization_code",
        "redirect_uri": settings.KEYCLOAK_LOGIN_REDIRECT_URL,
    }
    try:
        authorize_resp = httpx.post(
            url=settings.KEYCLOAK_TOKEN_URL,
            data=access_token_req
        )
        authorize_resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "status_code": 500,
                "status_message": "Internal Server Error",
                "error": "Error while retrieving token from the OpenID Provider"
            }
        )
    return