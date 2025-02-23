from fastapi import APIRouter, Depends
from app.deps import session_store
from app.schemas.oidc import AccessTokenClaims

router = APIRouter(
    prefix="/protected",
    tags=["protected"]
)


@router.get("")
def test_protected(access_token: AccessTokenClaims = Depends(session_store.verify_session)):
    """This endpoint requires a user to be logged in

    Args:
        token_data (AccessTokenPayload, optional): Decoded and valid access_token provided via Bearer Auth.

    Returns:
        dict: Simple success message
    """
    return access_token.model_dump()
