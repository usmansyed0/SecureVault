import time
import pytest
from fastapi import HTTPException
from app.rate_limiter import check_rate_limit, check_rate_limit_async, _memory_store


def test_rate_limiter_allows_requests_within_limit():
    key = f"test-allow-{time.time()}"
    # Should allow 5 requests
    for _ in range(5):
        check_rate_limit(key, max_requests=5, window=60)


def test_rate_limiter_blocks_requests_over_limit():
    key = f"test-block-{time.time()}"
    for _ in range(3):
        check_rate_limit(key, max_requests=3, window=60)

    # 4th request must raise HTTP 429
    with pytest.raises(HTTPException) as exc_info:
        check_rate_limit(key, max_requests=3, window=60)

    assert exc_info.value.status_code == 429
    assert "Rate limit exceeded" in exc_info.value.detail
    assert "Retry-After" in exc_info.value.headers


@pytest.mark.asyncio
async def test_async_rate_limiter_in_memory_fallback():
    key = f"test-async-{time.time()}"
    for _ in range(4):
        await check_rate_limit_async(key, max_requests=4, window=60)

    with pytest.raises(HTTPException) as exc_info:
        await check_rate_limit_async(key, max_requests=4, window=60)

    assert exc_info.value.status_code == 429
