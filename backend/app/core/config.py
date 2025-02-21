import os
from pathlib import Path
from typing import Any, Annotated, Literal
from pydantic import AnyUrl, BeforeValidator, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

def parse_cors(v: Any) -> list[str] | str:
    if isinstance(v, str) and not v.startswith("["):
        if v == "":
            return []
        return [i.strip() for i in v.split(",")]
    elif isinstance(v, list | str):
        return v
    raise ValueError(v)

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8"
    )

    FASTAPI_BASE_URI: str = "/api"
    # Allowed Cross Origin Request origins
    FASTAPI_BACKEND_CORS_ORIGINS: Annotated[
        list[AnyUrl] | str, BeforeValidator(parse_cors)
    ] = []
    FASTAPI_DOMAIN: str
    FASTAPI_PORT: int
    # FastAPI/OpenAPI project name
    FASTAPI_ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    FASTAPI_PROJECT_NAME: str
    # http/https
    FASTAPI_PROTOCOL: str = "http"

    @computed_field
    @property
    def FASTAPI_HOST(self) -> str:
        return f"{self.FASTAPI_PROTOCOL}://{self.FASTAPI_DOMAIN}:{self.FASTAPI_PORT}"

    # Path to the applications root folder, used for path construction
    # this will point to the app/ directory
    PROJECT_DIR: str = str(Path(__file__).resolve().parent.parent)

    KEYCLOAK_URL: str
    KEYCLOAK_REALM: str
    KEYCLOAK_CLIENT_ID: str
    KEYCLOAK_CLIENT_SECRET: str

    @computed_field
    @property
    def KEYCLOAK_OPENID_CONFIG_URL(self) -> str:
        return f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}/.well-known/openid-configuration"
    
    @computed_field
    @property
    def KEYCLOAK_TOKEN_URL(self) -> str:
        return f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}/protocol/openid-connect/token"
    
    @computed_field
    @property
    def KEYCLOAK_AUTH_URL(self) -> str:
        return f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}/protocol/openid-connect/auth"

    @computed_field
    @property
    def KEYCLOAK_LOGIN_REDIRECT_URL(self) -> str:
        return f"{self.FASTAPI_HOST}/api/v1/auth/callback"
    
    @computed_field
    @property
    def KEYCLOAK_LOGOUT_URL(self) -> str:
        return f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}/protocol/openid-connect/logout"

    # @computed_field
    # @property
    # def FASTAPI_HOST(self) -> str:
    #     return f"{self.FASTAPI_PROTOCOL}://{self.FASTAPI_DOMAIN}"

    # @computed_field
    # @property
    # def FASTAPI_URL(self) -> str:
    #     return f"{self.FASTAPI_HOST}/{self.FASTAPI_BASE_URI}"

settings = Settings()