import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from .config import settings


class Base(DeclarativeBase):
    pass


database_url = (
    settings.database_url
    or os.getenv("POSTGRES_URL", "")
    or os.getenv("DATABASE_URL", "")
).strip()
if database_url.startswith("postgres://"):
    database_url = "postgresql+psycopg2://" + database_url.removeprefix("postgres://")
elif database_url.startswith("postgresql://"):
    database_url = "postgresql+psycopg2://" + database_url.removeprefix("postgresql://")

if database_url:
    engine = create_engine(database_url, pool_pre_ping=True)
else:
    engine = create_engine(
        f"sqlite:///{settings.sqlite_path}", connect_args={"check_same_thread": False}
    )
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """
    Create all tables. Called on application startup.
    """
    # Import models so that they are registered with SQLAlchemy metadata
    from . import models  # noqa: F401

    if not database_url:
        settings.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

