from datetime import timedelta
from typing import Optional

from app.core.redis_config import redis_client
from app.core.settings import REFRESH_TOKEN_EXPIRE

TOKEN_BLACKLIST_PREFIX = "blacklist:"  # 토큰 블랙리스트 키 접두사
REFRESH_TOKEN_PREFIX = "refresh:"  # Refresh 토큰 저장 접두사
DEFAULT_TOKEN_EXPIRY = 60 * 30  # 토큰 유효 기간 (초)


class AsyncTokenService:
    """
    Redis asyncio 클라이언트를 사용하는 비동기 토큰 서비스
    """

    @classmethod
    async def blacklist_token(cls, token: str, expires_in: int = DEFAULT_TOKEN_EXPIRY) -> bool:
        key = f"{TOKEN_BLACKLIST_PREFIX}{token}"
        await redis_client.set(key, "1", ex=expires_in)
        return True

    @classmethod
    async def is_token_blacklisted(cls, token: str) -> bool:
        key = f"{TOKEN_BLACKLIST_PREFIX}{token}"
        return bool(await redis_client.exists(key))

    @classmethod
    async def clear_blacklist(cls) -> None:
        # 대량 삭제 최적화: 일괄 수집 후 delete(*keys)
        keys = []
        async for key in redis_client.scan_iter(match=f"{TOKEN_BLACKLIST_PREFIX}*"):
            keys.append(key)
        if keys:
            await redis_client.delete(*keys)

    @classmethod
    async def store_refresh_token(cls, user_id: int, refresh_token: str) -> bool:
        user_key = f"{REFRESH_TOKEN_PREFIX}{user_id}"

        expire_seconds = int(timedelta(days=REFRESH_TOKEN_EXPIRE + 1).total_seconds())
        print("store_refresh_token expire_seconds: ", expire_seconds)

        # asyncio 파이프라인
        async with redis_client.pipeline(transaction=True) as pipe:
            await pipe.sadd(user_key, refresh_token)
            await pipe.expire(user_key, expire_seconds)
            await pipe.execute()

        return True

    @classmethod
    async def validate_refresh_token(cls, user_id: int, refresh_token: str) -> bool:
        user_key = f"{REFRESH_TOKEN_PREFIX}{user_id}"
        return bool(await redis_client.sismember(user_key, refresh_token))

    @classmethod
    async def revoke_refresh_token(cls, user_id: int, refresh_token: Optional[str] = None) -> bool:
        user_key = f"{REFRESH_TOKEN_PREFIX}{user_id}"
        if refresh_token:
            await redis_client.srem(user_key, refresh_token)
        else:
            await redis_client.delete(user_key)
        return True
