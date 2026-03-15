# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Redis-backed state loader for the JWT Identity Linker.

Key format: {prefix}{sub}
Value format: JSON string with state_version and domain fields

The caller cannot influence which state is loaded — only the
verified JWT sub claim determines the Redis key.
"""
from __future__ import annotations

import json
from decimal import Decimal
from typing import Any

from pramanix.identity.linker import IdentityClaims, StateLoadError


class RedisStateLoader:
    """Loads state from Redis keyed by JWT sub claim.

    Usage:
        import redis.asyncio as redis
        r = redis.from_url("redis://localhost:6379")
        loader = RedisStateLoader(redis_client=r)
    """

    def __init__(
        self,
        redis_client: Any,
        key_prefix: str = "pramanix:state:",
    ) -> None:
        self._redis = redis_client
        self._prefix = key_prefix

    async def load(self, claims: IdentityClaims) -> dict[str, Any]:
        """Load state for claims.sub from Redis.

        Raises StateLoadError if key missing, value invalid,
        or state_version absent.
        """
        if not claims.sub:
            raise StateLoadError("JWT sub claim is empty — cannot load state")

        key = f"{self._prefix}{claims.sub}"

        try:
            raw = await self._redis.get(key)
        except Exception as e:
            raise StateLoadError(f"Redis error loading state: {e}") from e

        if raw is None:
            raise StateLoadError(
                f"No state found for sub={claims.sub!r}. "
                "Pre-load state into Redis before requests arrive."
            )

        try:
            state = json.loads(raw, parse_float=Decimal)
        except json.JSONDecodeError as e:
            raise StateLoadError(f"Invalid JSON in state for sub={claims.sub!r}: {e}") from e

        if "state_version" not in state:
            raise StateLoadError(
                f"State for sub={claims.sub!r} missing required field: state_version"
            )

        return dict(state)
