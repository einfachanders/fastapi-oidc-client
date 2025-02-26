class UnexpectedTokenTypeError(Exception):
    def __init__(self, expected_type: str, received_type: str):
        super().__init__(f"Unexpected token type received, expected: {expected_type}, received: {received_type}")


class InvalidNonceError(Exception):
    def __init__(self):
        super().__init__(f"OIDC nonce mismatch")
