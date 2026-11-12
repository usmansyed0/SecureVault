"""
Distributed Rate Limiter for SecureVault API.

Phase 4: Replaces PostgreSQL table-based rate limiting with Redis (e.g. Upstash,
managed Redis, or Valkey) and an in-memory sliding window fallback.

Benefits:
- Eliminates synchronous database round-trips and PostgreSQL row-lock contention.
- Operates in-memory (<1ms latency) with zero database overhead.
- Supports multi-instance distributed deployments via Redis.
"""

from __future__ import annotations

import collections
import threading
import time
from typing import Optional
from fastapi import HTTPException, Request

from .config import get_settings
from .logging_config import get_logger

_log = get_logger(__name__)

# In-memory sliding window state: key -> list of float timestamps
_memory_store: dict[str, list[float]] = collections.defaultdict(list)
_memory_lock = threading.Lock()

# Async Redis client cache
_redis_client = None
_redis_init_attempted = False


def _get_redis_client():
    global _redis_client, _redis_init_attempted
    if _redis_init_attempted:
        return _redis_client

    _redis_init_attempted = True
    try:
        settings = get_settings()
        if settings.redis_url:
            import redis.asyncio as aioredis
            _redis_client = aioredis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0
            )
            _log.info("redis_rate_limiter_initialized", url=settings.redis_url.split("@")[-1])
    except Exception as e:
        _log.warning("redis_rate_limiter_init_failed_falling_back_to_memory", error=str(e))
        _redis_client = None

    return _redis_client


def check_rate_limit(key: str, max_requests: int = 10, window: int = 60) -> None:
    """
    Synchronous rate limiter check using high-performance in-memory sliding window.
    Guarantees no database connections or table locking are incurred.
    """
    now = time.time()
    cutoff = now - window

    with _memory_lock:
        timestamps = _memory_store[key]
        # Drop timestamps outside current window
        valid = [ts for ts in timestamps if ts > cutoff]
        if len(valid) >= max_requests:
            retry_after = int(window - (now - valid[0])) + 1
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Try again in {max_requests} seconds.",
                headers={"Retry-After": str(max(1, retry_after))}
            )
        valid.append(now)
        _memory_store[key] = valid


async def check_rate_limit_async(key: str, max_requests: int = 10, window: int = 60) -> None:
    """
    Async rate limit check: attempts Redis if configured, falls back to in-memory window.
    """
    r = _get_redis_client()
    if r is not None:
        try:
            redis_key = f"rl:{key}"
            pipe = r.pipeline()
            pipe.incr(redis_key)
            pipe.expire(redis_key, window)
            results = await pipe.execute()
            current_count = results[0]
            if current_count > max_requests:
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded. Please slow down.",
                    headers={"Retry-After": str(window)}
                )
            return
        except HTTPException:
            raise
        except Exception as e:
            _log.warning("redis_rate_limit_error_falling_back_to_memory", error=str(e))

    # In-memory fallback
    check_rate_limit(key, max_requests=max_requests, window=window)


def auth_rate_limiter(request: Request) -> None:
    """Per-IP burst protection for authentication endpoints."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    check_rate_limit(f"ip:{client_ip}", max_requests=30, window=60)
