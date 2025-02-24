from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional
from uuid import UUID

class AuthorizationResponse(BaseModel):
    state: str = Field(description="OAuth state")
    # End-User login state on the OpenID Provider (OP) as per
    # https://openid.net/specs/openid-connect-session-1_0.html#CreatingUpdatingSessions
    session_state: str = Field(description="End-User login state at the OpenID Provider")
    # OAuth2 Issuer as per https://datatracker.ietf.org/doc/html/rfc9207
    iss: str = Field(description="Identity of the Authorization Server")
    code: str = Field(description="OAuth Authorization Code Flow code")


class TokenIntrospectionResponse(BaseModel):
    """OAuth token introspection response as per
    https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
    """
    active: bool = Field(description="Required: Indicates whether the access token "
                         "is still valid")
    aud: Optional[list[str]] | str = Field(
        default=None,
        description="Required: Intended JWT recipients"
    )
    client_id: Optional[str] = Field(
        default=None,
        description="Optional: ID of the client that requested the token"
    )
    exp: Optional[datetime] = Field(
        default=None,
        description="Optional: Expiry time of token"
    )
    iat: Optional[datetime] = Field(
        default=None,
        description="Required: Time of token issuance"
    )
    iss: Optional[str] = Field(
        default=None,
        description="Identity of the Authorization Server"
    )
    jti: Optional[UUID] = Field(
        default=None,
        description="Required: Unique JWT identifier"
    )
    nbf: Optional[datetime] = Field(
        default=None,
        description="Required: Timestampt the token should not be used before"
    )
    scope: Optional[str] = Field(
        default=None,
        description="Optional: List of scopes associated with the token"
    )
    sub: Optional[UUID] = Field(
        default=None,
        description="Required: Subject Identifier"
    )
    token_type: Optional[str] = Field(
        default=None,
        description="Optional: Type of the token"
    )
    username: Optional[str] = Field(
        default=None,
        description="Optional: Resource owner who authorized this token"
    )    


class CommonTokenClaims(BaseModel):
    acr: Optional[str] = Field(
        default=None,
        description="Optional: Authentication Context Class Reference"
    )
    aud: list[str] | str = Field(description="Required: Intended JWT recipients")
    azp: Optional[str] = Field(
        default=None,
        description="Optional: Party the token was issued to"
    )
    auth_time: Optional[datetime] = Field(
        default=None,
        description="Optional: Time when the End-User authentication occurred"
    )
    email: Optional[str] = Field(
        default=None,
        description="Optional: E-Mail address of the subject"
    )
    email_verified: Optional[bool] = Field(
        default=None,
        description="Optional: E-Mail verification status of the subject in Keycloak"
    )
    exp: datetime = Field(description="Required: Expiry time of token")
    family_name: Optional[str] = Field(
        default=None,
        description="Optional: Family name of the subject"
    )
    given_name: Optional[str] = Field(
        default=None,
        description="Optional: Given name of the subject"
    )
    iat: datetime = Field(description="Required: Time of token issuance")
    iss: str = Field(description="Identity of the Authorization Server")
    jti: UUID = Field(description="Required: Unique JWT identifier")
    name: Optional[str] = Field(
        default=None,
        description="Optional: Full name of the subject"
    )
    preferred_username: Optional[str] = Field(
        default=None,
        description="Optional: Preferred username of the subject"
    )
    sid: UUID = Field(description="Required: Session identifier")
    sub: UUID = Field(description="Required: Subject Identifier")
    typ: Optional[str] = Field(
        default=None,
        description="Optional: Token type"
    )


class RealmAccess(BaseModel):
    roles: list[str] = Field(description="User roles in the Keycloak realm")
    

class ResourceRoles(BaseModel):
    roles: list[str] = Field(description="User roles")


class AccessTokenClaims(CommonTokenClaims):
    allowed_origins: Optional[list[str]] = Field(
        default=None,
        description="Optional: Allowed request origins (i think?)"
    )
    realm_access: Optional[RealmAccess] = Field(
        default=None,
        description="Optional: User roles in the Keycloak realm"
    )
    resource_access: Optional[dict[str, "ResourceRoles"]] = Field(
        default=None,
        description="Optional: User specific access roles per resource as defined in Keycloak"
    )
    scope: str = Field(description="Required: Requested OAuth scopes")


class IDTokenClaims(CommonTokenClaims):
    at_hash: Optional[str] = Field(
        default=None,
        description="Optional: Access Token hash value"
    )
    nonce: str = Field(description="Required: OpenID Nonceused to associate a Client session "
                       "with an ID Token and to mitigate replay attacks")


class LogoutTokenClaims(BaseModel):
    iss: str = Field(description="Identity of the Authorization Server")
    sub: Optional[UUID] = Field(
        default=None,
        description="Required: Subject Identifier"
    )
    aud: list[str] | str = Field(description="Required: Intended JWT recipients")
    iat: datetime = Field(description="Required: Time of token issuance")
    exp: datetime = Field(description="Required: Expiry time of token")
    jti: UUID = Field(description="Required: Unique JWT identifier")
    events: dict = Field(description="Required: Indicates this token is a logout token")
    sid: UUID = Field(description="Required: Session identifier")
