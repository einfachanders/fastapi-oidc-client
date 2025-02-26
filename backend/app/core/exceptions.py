import http
from fastapi import HTTPException


ERROR_MESSAGES = {
    "invalid_claims": "Invalid token claims",
    "invalid_cookie_signature": "Invalid cookie signature",
    "invalid_session": "Session is invalid",
    "invalid_state": "Invalid OAuth state",
    "invalid_token": "Invalid token provided",
    "invalid_token_signature": "Invalid token signature",
    "missing_cookie": "oauth_session cookie missing",
    "op_token_validation_failed": "Error while validating the OPs token response",
    "token_expired": "Token is expired",
    "token_refresh_failed": "Error while performing the token refresh",
    "token_retrieval_failed": "Error while retrieving the token from the OP",
    "unexpected_issuer": "Unexpected issuer",
    "unexpected_token": "Unexpected token type received"
}

class UnexpectedTokenTypeError(Exception):
    def __init__(self, expected_type: str, received_type: str):
        super().__init__(f"Unexpected token type received, expected: {expected_type}, received: {received_type}")

class InvalidNonceError(Exception):
    def __init__(self):
        super().__init__(f"OIDC nonce mismatch")

def _get_status_line(status_code: int) -> str:
    try:
        phrase = http.HTTPStatus(status_code).phrase
    except ValueError:
        phrase = ""
    return "".join([str(status_code), " ", phrase])

STATUS_LINE = {status_code: _get_status_line(status_code) for status_code in range(100, 600)}

def http_error(status_code: int, error_message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"status": STATUS_LINE[status_code], "error": error_message})
