from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base for every ORM model in zeroshield.db, and the
    target metadata Alembic migrations are generated/checked against
    (see alembic/env.py)."""
