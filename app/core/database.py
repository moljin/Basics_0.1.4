from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

from app.core.config import get_config

config = get_config()
print(f"config.DEBUG: {config.DEBUG}")
# DATABASE_URL = "sqlite+aiosqlite:///./sql_app.db" # # 또는 config.APPLIED_DB # SQLite 비동기 드라이버 사용
DATABASE_URL = f"{config.DB_TYPE}+{config.DB_DRIVER}://{config.DB_USER}:{config.DB_PASSWORD}@{config.DB_HOST}:{config.DB_PORT}/{config.DB_NAME}?charset=utf8"

ASYNC_ENGINE = create_async_engine(DATABASE_URL,
                                   echo=config.DEBUG,
                                   future=True,
                                   pool_size=10, max_overflow=0, pool_recycle=300, # 5분마다 연결 재활용
                                   # encoding="utf-8"
                                   )

# 세션 로컬 클래스 생성
AsyncSessionLocal = async_sessionmaker(
    ASYNC_ENGINE,
    class_=AsyncSession, # add
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
    # poolclass=NullPool,  # SQLite에서는 NullPool 권장

)

# Base 클래스 (모든 모델이 상속)
Base = declarative_base()

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    session: AsyncSession = AsyncSessionLocal()
    print(f"[get_session] new session: {id(session)}")
    try:
        yield session
    except Exception as e:
        print(f"Session rollback triggered due to exception: {e}")
        await session.rollback()
        raise
    finally:
        print(f"[get_session] close session: {id(session)}")
        await session.close()

"""
pip install pymysql
pip install sqlalchemy
pip install alembic
pip install aiomysql

1. alembic init migration
    1-1 alembic.ini
        sqlalchemy.url = mysql+aiomysql://root:981011@localhost:3306/testdb?charset=utf8mb4
    1-2 migration/env.py 파일 수정

2. mysql db에 testdb(db명)를 생성해 놓아야 한다.
    alembic revision --autogenerate -m "create users table"
    alembic upgrade head
"""



