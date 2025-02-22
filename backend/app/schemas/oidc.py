from pydantic import BaseModel, Field

class AuthorizationResponse(BaseModel):
    state: str = Field(description="OAuth state")
    # End-User login state on the OpenID Provider (OP) as per
    # https://openid.net/specs/openid-connect-session-1_0.html#CreatingUpdatingSessions
    session_state: str = Field(description="End-User login state at the OpenID Provider")
    # OAuth2 Issuer as per https://datatracker.ietf.org/doc/html/rfc9207
    iss: str = Field(description="Identity of the Authorization Server")
    code: str = Field(description="OAuth Authorization Code Flow code")