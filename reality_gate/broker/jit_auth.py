"""
REALITY-GATE v2.0 — Cryptographic HMAC-SHA256 Short-Lived JIT Lease Broker
Mints signed JWT-style leases (`header.payload.signature`) with 60s expiry,
single-use nonce binding, and SQLite persistence for strict replay protection.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Dict, Optional

from reality_gate.config import DEFAULT_JIT_TTL_SEC, JIT_HMAC_SECRET
from reality_gate.database import DatabaseManager
from reality_gate.models import JITLease


class BrokerSecurityError(Exception):
    """Raised when cryptographic lease verification, replay protection, or broker scoping fails."""

    def __init__(self, reason_code: str, message: str, status_code: int = 403):
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message
        self.status_code = status_code


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded: str) -> bytes:
    pad = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode((encoded + pad).encode("ascii"))


class JITAuthBroker:
    def __init__(self, db: DatabaseManager, secret: bytes = JIT_HMAC_SECRET):
        self.db = db
        self._secret = secret

    def _sign_parts(self, header_b64: str, payload_b64: str) -> str:
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        digest = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        return _b64url_encode(digest)

    def mint_lease(
        self,
        tenant_id: str,
        change_id: str,
        operation: str,
        target_cidr: str,
        ttl_seconds: int = DEFAULT_JIT_TTL_SEC,
        nonce: Optional[str] = None,
    ) -> JITLease:
        now = int(time.time())
        exp = now + max(1, int(ttl_seconds))
        token_id = f"JIT-RG-{uuid.uuid4().hex[:8].upper()}"
        lease_nonce = nonce or f"NONCE-{uuid.uuid4().hex[:12].upper()}"

        header = {"alg": "HS256", "typ": "RG-JIT+JWT"}
        payload = {
            "jti": token_id,
            "sub": tenant_id,
            "chg": change_id,
            "op": operation.upper().strip(),
            "cidr": target_cidr,
            "nonce": lease_nonce,
            "iat": now,
            "exp": exp,
        }
        h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        sig_b64 = self._sign_parts(h_b64, p_b64)
        jwt_token = f"{h_b64}.{p_b64}.{sig_b64}"

        lease = JITLease(
            token_id=token_id,
            jwt_token=jwt_token,
            nonce=lease_nonce,
            tenant_id=tenant_id,
            change_id=change_id,
            operation=operation.upper().strip(),
            target_cidr=target_cidr,
            issued_epoch=now,
            expires_epoch=exp,
            ttl_seconds=ttl_seconds,
            hmac_signature=sig_b64,
            used=False,
        )
        self.db.store_lease(lease.model_dump())
        return lease

    def verify_jwt_signature(self, jwt_token: str) -> Dict[str, Any]:
        parts = jwt_token.split(".")
        if len(parts) != 3:
            raise BrokerSecurityError(
                "INVALID_JWT_FORMAT",
                "DENY (403): Authorization token is not a valid HMAC-SHA256 signed JIT lease.",
            )
        h_b64, p_b64, sig_b64 = parts
        expected_sig = self._sign_parts(h_b64, p_b64)
        if not hmac.compare_digest(sig_b64, expected_sig):
            raise BrokerSecurityError(
                "INVALID_HMAC_SIGNATURE",
                "DENY (403): HMAC-SHA256 signature verification failed on JIT lease.",
            )
        try:
            payload = json.loads(_b64url_decode(p_b64).decode("utf-8"))
        except Exception as exc:
            raise BrokerSecurityError(
                "CORRUPTED_JWT_PAYLOAD",
                f"DENY (403): Could not decode JIT lease payload: {exc}",
            )
        return payload

    def verify_and_consume_lease(
        self,
        *,
        tenant_id: str,
        authorization_token: str,
        nonce: str,
        operation: str,
        target_cidr: str,
        now_epoch: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Verify HMAC-SHA256 signature, expiry, scope binding, and single-use SQLite nonce."""
        if not authorization_token:
            raise BrokerSecurityError(
                "MISSING_AUTHORIZATION_TOKEN",
                "DENY (403): Execution Broker requires a signed HMAC-SHA256 JIT lease token.",
            )

        lease = self.db.get_lease(authorization_token)
        if not lease:
            # Also check if a forged JWT was presented directly
            if "." in authorization_token:
                self.verify_jwt_signature(authorization_token)
            raise BrokerSecurityError(
                "INVALID_OR_UNKNOWN_TOKEN",
                "DENY (403): Execution Broker rejected unknown or unissued authorization token.",
            )

        # Always cryptographically verify the stored/provided JWT signature
        jwt_to_check = authorization_token if "." in authorization_token else lease["jwt_token"]
        payload = self.verify_jwt_signature(jwt_to_check)

        if lease["tenant_id"] != tenant_id:
            raise BrokerSecurityError(
                "TENANT_SCOPE_MISMATCH",
                f"DENY (403): Lease bound to tenant '{lease['tenant_id']}', cannot execute in '{tenant_id}'.",
            )

        # Single-use & nonce replay protection persisted in SQLite
        effective_nonce = nonce or lease["nonce"]
        if lease["used"] or self.db.is_nonce_used(lease["nonce"]) or (
            effective_nonce and self.db.is_nonce_used(effective_nonce)
        ):
            raise BrokerSecurityError(
                "REPLAY_TOKEN_REJECTED",
                "DENY (403): Replay attack detected — JIT lease token or nonce has already been consumed.",
            )

        if nonce and nonce != lease["nonce"]:
            raise BrokerSecurityError(
                "NONCE_MISMATCH",
                "DENY (403): Presented anti-replay nonce does not match signed JIT lease payload.",
            )

        now = int(time.time()) if now_epoch is None else int(now_epoch)
        if now > int(lease["expires_epoch"]) or now > int(payload.get("exp", 0)):
            raise BrokerSecurityError(
                "TOKEN_EXPIRED",
                "DENY (403): Short-lived 60s JIT execution lease has expired.",
            )

        req_op = operation.upper().strip()
        if lease["operation"] != req_op or lease["target_cidr"] != target_cidr:
            raise BrokerSecurityError(
                "TOKEN_SCOPE_MISMATCH",
                f"DENY (403): JIT lease is strictly scoped to {lease['operation']} on {lease['target_cidr']}, "
                f"not {req_op} on {target_cidr}.",
            )

        # Consume lease + nonce atomically in SQLite
        self.db.mark_lease_used(lease["token_id"])
        self.db.consume_nonce(lease["nonce"], tenant_id)
        return lease
