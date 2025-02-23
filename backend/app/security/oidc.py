import os
import base64
import hashlib
import httpx
import json
import jose.exceptions
from cachetools import TTLCache
from jose import jws, jwt
from fastapi import HTTPException
from app.core.config import settings
from app.schemas.oidc import AccessTokenClaims, IDTokenClaims, TokenIntrospectionResponse


jwks_cache = TTLCache(maxsize=10, ttl=600)


async def autorize(code: str, code_verifier: str) -> None:
    """Performs the OAuth/OIDC token request

    Args:
        code (str): Authorization Code Flow code
        code_verifier (str): PKCE code verifier

    Raises:
        HTTPException: Raised in case the token request
            was unsuccessful
    """
    access_token_req = {
        "client_id": settings.KEYCLOAK_CLIENT_ID,
        "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
        "code": code,
        "code_verifier": code_verifier,
        "grant_type": "authorization_code",
        "redirect_uri": settings.KEYCLOAK_LOGIN_REDIRECT_URL,
        "scope": "openid"
    }
    try:
        authorize_resp = httpx.post(
            url=settings.KEYCLOAK_TOKEN_URL,
            data=access_token_req
        )
        authorize_resp.raise_for_status()
        return authorize_resp.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "status_code": 500,
                "status_message": "Internal Server Error",
                "error": "Error while retrieving token from the OpenID Provider"
            }
        )


async def logout(refresh_token: str) -> None:
    """Log out a user's session using the user agents refresh_token against the IDP

    Args:
        refresh_token (str): User agents refresh token

    Raises:
        HTTPException: HTTP Exception returned to user agent in case of an error
    """
    logout_request = {
            "refresh_token": refresh_token,
            "client_id": settings.KEYCLOAK_CLIENT_ID,
            "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
    }
    try:
        response = httpx.post(settings.KEYCLOAK_LOGOUT_URL, data=logout_request)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "status_code": 500,
                "status_message": "Internal Server Error",
                "error": "Error while logging out at the OpenID Provider"
            }
        )


async def refresh(refresh_token: str):
    refresh_request = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": settings.KEYCLOAK_CLIENT_ID,
        "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
    }
    try:
        refresh_response = httpx.post(
            settings.KEYCLOAK_TOKEN_URL,
            data=refresh_request
        )
        refresh_response.raise_for_status()
        return refresh_response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "status_code": 500,
                "status_message": "Internal Server Error",
                "error": "Error while requesting token refresh from the OpenID Provider"
            }
        )


async def _get_jwks(kid: str) -> dict:
    """Get a signature key from the OpenID Provider/OAuth Authorization
    Server. Utilizes a TTLCache to prevent querying the OP/AS for every
    token verification

    Args:
        kid (str): ID of the key to retrieve

    Returns:
        dict: Dictionary with the key details
    """
    if kid in jwks_cache:
        return jwks_cache[kid]
    jwks_response = httpx.get(settings.KEYCLOAK_JWKS_URL).json()
    for key in jwks_response["keys"]:
        if key["kid"] == kid:
            jwks_cache[kid] = key
            return key


async def gen_oauth_code_challenge() -> tuple[str, str]:
    """Generates a PKCE code verifier and code challenge as per
    https://datatracker.ietf.org/doc/html/rfc7636#section-4.1

    Returns:
        tuple[str, str]: _description_
    """
    # urlsafe_b64encode does not remove "=" padding, needs to be
    # done manually
    code_verifier = base64.urlsafe_b64encode(
        os.urandom(32)
    ).decode().rstrip("=")
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")
    return code_verifier, code_challenge


async def gen_oauth_state(state_length: int = 16) -> str:
    """Generates an OAuth state as per 
    https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1

    Args:
        state_length (int, optional): Length of the state in bytes. Defaults to 16.

    Returns:
        str: OAuth state as hex string
    """
    state = os.urandom(state_length).hex()
    return state


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


async def gen_oidc_auth_req_url(code_challenge: str, oauth_state: str, oidc_nonce: str) -> str:
    """Generates an OIDC authentication request url for user agent redirection
    as per https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest

    Args:
         code_verifier (str): PKCE code verifier
        oidc_nonce (str): OIDC nonce
        oauth_state (str): OAuth state

    Returns:
        str: OIDC authentication request url
    """
    oidc_query_params = {
        "client_id": settings.KEYCLOAK_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": settings.KEYCLOAK_LOGIN_REDIRECT_URL,
        "scope": "openid",
        "state": oauth_state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": oidc_nonce
    }
    return f"{settings.KEYCLOAK_AUTH_URL}?{httpx.QueryParams(oidc_query_params)}"


async def gen_oidc_nonce(nonce_length: int = 16) -> str:
    """Generates an OIDC Nonce as per 
    https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes

    Args:
        nonce_length (int, optional): Length of the nonce in bytes. Defaults to 16.

    Returns:
        str: OIDC nonce as hex string
    """
    nonce = os.urandom(nonce_length).hex()
    return nonce


async def verify_auth_jws(oauth_session_jws: str) -> dict:
    """Verifies an OAuth session in form of a JSON Web Signature
    extracted from a cookie

    Args:
        oauth_session_jws (str): OAuth session JWS

    Returns:
        dict: OAuth session information
    """
    oauth_session = jws.verify(
        token=oauth_session_jws,
        key=settings.FASTAPI_JWS_SECRET,
        algorithms="HS256"
    )
    return json.loads(oauth_session.decode())


async def token_introsepction(access_token: str) -> bool:
    """Performs a OAuth token introspection request to 
    check the validity of a provided access token

    Args:
        access_token (str): Access token to perform introspecetion for

    Raises:
        HTTPException: Raised in case the introspection request fails

    Returns:
        bool: Active state of the access token
    """
    introspection_post_data  = {
        "client_id": settings.KEYCLOAK_CLIENT_ID,
        "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
        "token": access_token
    }
    try:
        introspection_response = httpx.post(
            url=settings.KEYCLOAK_TOKEN_INTROSPECTION_ENDPONT,
            data=introspection_post_data
        )
        introspection_response.raise_for_status()
        print(introspection_response.json())
    except httpx.HTTPStatusError as exc:
        print(introspection_response.text)
        raise HTTPException(
            status_code=500,
            detail={
                "status_code": 500,
                "status_message": "Internal Server Error",
                "error": "Error while performing token introspection"
            }
        )
    introspection_response =  TokenIntrospectionResponse(**introspection_response.json())
    return introspection_response.active


async def verify_access_token(access_token: str) -> AccessTokenClaims:
    """Verify an OAuth access token

    Args:
        access_token (str): Access token to verify

    Raises:
        HTTPException: Raised in case an unexpected token type
            was provided

    Returns:
        AccessTokenClaims: Pydantic model of the access token claims
    """
    header = jwt.get_unverified_header(access_token)
    key = await _get_jwks(header["kid"])
    # verify token signature, audience and issuer
    try:
        claims = jwt.decode(
            token=access_token,
            key=key,
            audience=settings.KEYCLOAK_CLIENT_ID,
            issuer=settings.KEYCLOAK_ISSUER
        )
    except jose.exceptions.JWSSignatureError as error:
        raise HTTPException(
            status_code=401,
            detail={
                "status_code": 401,
                "status_message": "Unauthorized",
                "error": "Unable to verify token signature"
            }
        )
    except jose.exceptions.ExpiredSignatureError as error:
        raise HTTPException(
            status_code=401,
            detail={
                "status_code": 401,
                "status_message": "Unauthorized",
                "error": "Token has expired"
            }
        )
    # when we know the signature is ok, check whether the
    # token type indicates it is an access token
    if not claims["typ"] == "Bearer":
        raise HTTPException(
            status_code=400,
            detail={
                "status_code": 400,
                "status_message": "Bad Request",
                "error": "Unexpected token type"
            }
        )
    return AccessTokenClaims(**claims)


async def verify_id_token(id_token: str, access_token: str, nonce: str) -> IDTokenClaims:
    """Verify an OIDC ID token

    Args:
        id_token (str): ID token to verify
        access_token (str): OAuth access token to verify ID token at_hash claim
        nonce (str): OIDC nonce that should be claimed in the ID token

    Raises:
        HTTPException: Raised in case an unexpected token type was provided
        HTTPException: Raided in case the provided nonce does not match the
            nonce claimed in the token

    Returns:
        IDTokenClaims: Pydantic model of the ID token claims
    """
    header = jwt.get_unverified_header(id_token)
    key = await _get_jwks(header["kid"])
    # verify token signature, audience, issuer and
    # whether the access token matches the id token's 
    # at_hash claim
    claims = jwt.decode(
        token=id_token,
        key=key,
        audience=settings.KEYCLOAK_CLIENT_ID,
        issuer=settings.KEYCLOAK_ISSUER,
        access_token=access_token
    )
    # when we know the signature is ok, check whether the
    # token header indicates it is a jwt
    if not claims["typ"] == "ID":
        raise HTTPException(
            status_code=400,
            detail={
                "status_code": 400,
                "status_message": "Bad Request",
                "error": "Unexpected token type"
            }
        )
    # check whether the OpenID nonces match
    if not claims["nonce"] == nonce:
        raise HTTPException(
            status_code=400,
            detail={
                "status_code": 400,
                "status_message": "Bad Request",
                "error": "OpenID nonce mismatch"
            }
        )
    return IDTokenClaims(**claims)


async def verify_token_resp(token_resp: dict, oauth_session: dict) -> AccessTokenClaims:
    """Verify the token included in a OAuth/OIDC token request

    Args:
        token_resp (dict): OAuth/OIDC token response
        oauth_session (dict): OAuth session cookie content

    Returns:
        AccessTokenClaims: Pydantic model of the access token claims
    """
    verified_access_token = await verify_access_token(token_resp["access_token"])
    await verify_id_token(token_resp["id_token"], token_resp["access_token"], oauth_session["oidc_nonce"])
    return verified_access_token
