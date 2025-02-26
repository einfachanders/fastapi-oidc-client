from fastapi import Request
import jose.exceptions
from jose import jws
import json
from app.core import logging
from app.core.config import settings
from app.core.exceptions import http_error, ERROR_MESSAGES

logger = logging.get_logger(__name__)

async def gen_auth_jws(code_verifier: str, oidc_nonce: str, oauth_state: str) -> str:
    """Generates a jws containg the PKCE code verifier, OIDC nonce and the OAuth state
    for storage in a cookie

    Args:
        code_verifier (str): PKCE code verifier
        oidc_nonce (str): OIDC nonce
        oauth_state (str): OAuth state

    Returns:
        str: JSON Web Signature
    """
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


async def verify_auth_jws(oauth_session_jws: str) -> dict:
    """Verifies an OAuth session in form of a JSON Web Signature
    extracted from a cookie

    Args:
        oauth_session_jws (str): OAuth session JWS

    Returns:
        dict: OAuth session information
    """
    try:
        oauth_session = jws.verify(
            token=oauth_session_jws,
            key=settings.FASTAPI_JWS_SECRET,
            algorithms="HS256"
        )
    except jose.exceptions.JWSError as error:
        logger.error(f"Error while verifying the jws: {error}")
        raise jose.exceptions.JWSError("Signature verification failed.")
    return json.loads(oauth_session.decode())


async def get_oauth_session(request: Request):
    try:
        oauth_session_cookie = request.cookies["oauth_session"]
    except KeyError:
        raise http_error(400, ERROR_MESSAGES["missing_cookie"])

    try:
        return await verify_auth_jws(oauth_session_cookie)
    except jose.exceptions.JWSError:
        raise http_error(400, ERROR_MESSAGES["invalid_cookie_signature"])
