"""
Database Configuration
----------------------

This module handles:
- Database connection
- SQLAlchemy engine
- Database session
- Base class for database models

Default database:
SQLite

The database URL can be configured using the DATABASE_URL
environment variable.
"""

import importlib

try:
    sqlalchemy_module = importlib.import_module("sqlalchemy")
    create_engine = sqlalchemy_module.create_engine
    declarative_base = sqlalchemy_module.orm.declarative_base
    sessionmaker = sqlalchemy_module.orm.sessionmaker
except ModuleNotFoundError:  # pragma: no cover - optional dependency in minimal setup
    create_engine = None
    declarative_base = None
    sessionmaker = None

from app.core.config import DATABASE_URL


# ---------------------------------------------------------
# DATABASE ENGINE
# ---------------------------------------------------------

# SQLite requires this option when the application uses
# multiple threads, which is common with FastAPI.
connect_args = {}

if DATABASE_URL.startswith("sqlite"):
    connect_args = {
        "check_same_thread": False
    }


if create_engine is not None:
    engine = create_engine(
        DATABASE_URL,
        connect_args=connect_args,
        future=True
    )
else:
    engine = None


# ---------------------------------------------------------
# DATABASE SESSION
# ---------------------------------------------------------

if sessionmaker is not None and engine is not None:
    SessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False
    )
else:
    SessionLocal = None


# ---------------------------------------------------------
# DATABASE BASE
# ---------------------------------------------------------

if declarative_base is not None:
    Base = declarative_base()
else:
    Base = None


# ---------------------------------------------------------
# DATABASE DEPENDENCY
# ---------------------------------------------------------

def get_db():
    """
    Create a database session for a request.

    The session is automatically closed after
    the request is completed.
    """

    if SessionLocal is None:
        raise RuntimeError(
            "SQLAlchemy is not installed; database access is unavailable."
        )

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


# ---------------------------------------------------------
# CREATE DATABASE TABLES
# ---------------------------------------------------------

def init_db():
    """
    Create all database tables defined using SQLAlchemy models.

    If SQLAlchemy is unavailable or no mapped models exist,
    this function becomes a no-op instead of crashing import-time code.
    """

    if Base is None or engine is None:
        return

    try:
        # Import models here to make sure SQLAlchemy knows
        # about them before creating the tables.
        from app.models import alert  # type: ignore
    except ImportError:
        pass

    Base.metadata.create_all(
        bind=engine
    )