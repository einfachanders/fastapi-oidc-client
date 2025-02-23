from datetime import datetime
from pydantic import BaseModel, Field
from typing import Literal
from uuid import UUID

class Session(BaseModel):
    sub: UUID = Field(description="Subject identifier")
    exp: datetime = Field(description="Session expiry time")
    # state: Literal["valid", "invalid"] = Field(
    #     default="valid",
    #     description="State of the session"
    # )