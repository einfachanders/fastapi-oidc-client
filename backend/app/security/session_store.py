from datetime import datetime
import jose.exceptions
from uuid import UUID
from fastapi import Depends
from fastapi.security import OAuth2AuthorizationCodeBearer
from app.core.config import settings
from app.core.exceptions import UnexpectedTokenTypeError, http_error, ERROR_MESSAGES
from app.schemas.sessions import Session
from app.schemas.oidc import AccessTokenClaims
from app.security import oidc

# Idea: Freshly created access tokens using this client
# are directly added to session. For request providing
# a jwt with a session that is unknown, the token
# introspection endpoint is used. If a session is valid,
# it is added to the session store. If it is invalid,
# 401 is returned and the session is not added. For backchannel
# logouts, if that session is in the session store, it is 
# removed. If it is not in the session store, nothing is done
# since a request with a token referencing that sid will
# first be checked via the token introspection endpoint
# and the refused.

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=settings.KEYCLOAK_AUTH_URL,
    tokenUrl=settings.KEYCLOAK_TOKEN_URL
)

class SessionStore():
    def __init__(self):
        # all session in this session store SHOULD represent
        # valid session (i.e. session that have not been revoked
        # and are not expired)
        self.sessions: dict[UUID, Session] = {}


    async def cleanup_sessions(self) -> None:
        """Remove expired sessions from the session store
        """
        for session, session_data in self.sessions.items():
            if session_data.exp < datetime.now(session_data.exp.tzinfo):
                self.sessions.pop(session)


    async def invalidate_session(self, sid: UUID) -> None:
        """Remove a session from the session store (e.g. in case of
        backchannel logout)

        Args:
            sid (UUID): Session to remove
        """
        if sid in self.sessions.keys():
            self.sessions.pop(sid)


    async def update_session(self, sid: UUID, sub: UUID, exp: datetime) -> None:
        """Add a session to the session store or update an existing session
        in the session store

        Args:
            sid (UUID): Session ID
            sub (UUID): Session subject identifier
            exp (datetime): Session expiry
        """
        session = Session(sub=sub, exp=exp)
        self.sessions[sid] = session


    async def verify_session(self, access_token: str = Depends(oauth2_scheme)) -> AccessTokenClaims:
        """Verify a provided access token and its session id for validity

        Args:
            access_token (str): Access token to check validity of

        Raises:
            HTTPException: Raised in case the session is invalid

        Returns:
            AccessTokenClaims: Pydantic model of the access token claims
        """
        # verify the validity of the access token
        try:
            verified_access_token = await oidc.verify_access_token(access_token)
        # catch exceptions that might occur during token verification
        except jose.exceptions.JWSSignatureError as signature_error:
            raise http_error(401, ERROR_MESSAGES["invalid_token_signature"])
        except jose.exceptions.ExpiredSignatureError as expired_error:
            raise http_error(401, ERROR_MESSAGES["token_expired"])
        except jose.exceptions.JWTClaimsError as claims_error:
            raise http_error(401, ERROR_MESSAGES["invalid_claims"])
        except UnexpectedTokenTypeError as unexpected_token:
            raise http_error(401, ERROR_MESSAGES["unexpected_token"])
        except jose.exceptions.JWTError:
            raise http_error(401, ERROR_MESSAGES["invalid_token"])

        # check if session is known
        session = self.sessions.get(verified_access_token.sid, None)
        if session is None:
            # if session is not known, perform a token introspection to
            # check validity before adding it to the session store
            if not await oidc.token_introspection(access_token):
                raise http_error(401, ERROR_MESSAGES["invalid_session"])
        # add/update session (mainly the expiry date to prevent it from
        # getting cleaned up)
        await self.update_session(verified_access_token.sid, verified_access_token.sub,
                            verified_access_token.exp)
        return verified_access_token


class RedisSessionStore(SessionStore):
    pass
