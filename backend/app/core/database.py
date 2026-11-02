"""SentinelX Database Management (SQLAlchemy 2.x Async)
Supports both MySQL (aiomysql) and SQLite (aiosqlite) with connection pooling and timeouts.
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.models.base import Base

# Engine configuration depending on DB dialect
engine_kwargs = {
    "echo": settings.DEBUG,
    "future": True
}

if "sqlite" in settings.DATABASE_URL:
    # SQLite configuration
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    # MySQL / PostgreSQL connection pooling configuration
    engine_kwargs["pool_size"] = settings.DB_POOL_SIZE
    engine_kwargs["max_overflow"] = settings.DB_MAX_OVERFLOW
    engine_kwargs["pool_timeout"] = settings.DB_POOL_TIMEOUT
    engine_kwargs["pool_pre_ping"] = True

engine = create_async_engine(settings.DATABASE_URL, **engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI Dependency for database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database tables with connection timeout."""
    try:
        async with asyncio.timeout(3.0):
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        logger.info("Database schema initialized successfully.")
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Database connection or initialization deferred ({e}). Operating in resilient mode.")

