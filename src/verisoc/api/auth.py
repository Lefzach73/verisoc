from dataclasses import dataclass
from uuid import UUID

import jwt

from verisoc.core.errors import Unauthorized


@dataclass(frozen=True)
class Auth:
    signing_key: str
    issuer: str = "verisoc-research"
    audience: str = "verisoc-api"

    def __post_init__(self) -> None:
        if len(self.signing_key.encode()) < 32:
            raise ValueError("At least 32-byte server signing key required")

    def tenant(self, authorization: str | None) -> UUID:
        if not authorization or not authorization.startswith("Bearer "):
            raise Unauthorized("Authentication required")
        try:
            payload = jwt.decode(
                authorization[7:],
                self.signing_key,
                algorithms=["HS256"],
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["exp", "iat", "nbf", "sub", "tenant_id", "iss", "aud"]},
            )
            if not isinstance(payload["sub"], str) or not payload["sub"]:
                raise ValueError("Invalid subject")
            return UUID(payload["tenant_id"])
        except (jwt.PyJWTError, ValueError, TypeError, KeyError) as exc:
            raise Unauthorized("Authentication required") from exc
