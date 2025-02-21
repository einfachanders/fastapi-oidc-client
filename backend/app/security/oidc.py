# stdlib imports
import os
import base64
import hashlib
import httpx
from cachetools import TTLCache
# local module imports
from app.core.config import settings

state_cache = TTLCache(maxsize=float('inf'), ttl=120)

def init_pkce_flow() -> None:
    # generate a 128 bit oauth state
    oauth_state = os.urandom(16).hex()

    # generate code_verifier https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
    oauth_code_verifier = os.urandom(32)
    oauth_code_verifier_encoded = base64.urlsafe_b64encode(oauth_code_verifier)
    # make url safe (i.e. remove "=")
    oauth_code_verifier_encoded = str(oauth_code_verifier_encoded).rstrip("=")
    oauth_code_verifier_challenge = hashlib.sha256(oauth_code_verifier_encoded.encode()).hexdigest()

    # generate oidc nonce https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
    oidc_nonce = os.urandom(32).hex()

    # return constructed redirect url
    oidc_query_params = {
        "client_id": settings.KEYCLOAK_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": settings.KEYCLOAK_LOGIN_REDIRECT_URL,
        "scope": "openid email profile",
        "state": oauth_state,
        "code_challenge": oauth_code_verifier_challenge,
        "code_challenge_method": "S256",
        "nonce": oidc_nonce
    }
    return f"{settings.KEYCLOAK_AUTH_URL}?{httpx.QueryParams(oidc_query_params)}"
