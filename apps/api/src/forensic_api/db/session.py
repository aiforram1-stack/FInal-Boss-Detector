"""Database construction with SQLite foreign keys enabled on every connection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from forensic_api.db.models import Base


@dataclass(slots=True)
class Database:
    engine: Engine
    sessions: sessionmaker[Session]

    def create_schema_for_tests(self) -> None:
        Base.metadata.create_all(self.engine)

    def healthcheck(self) -> bool:
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return True
        except Exception:
            return False


def build_database(database_url: str) -> Database:
    connect_args: dict[str, Any] = {"check_same_thread": False}
    engine = create_engine(database_url, connect_args=connect_args, future=True)

    @event.listens_for(engine, "connect")
    def enable_sqlite_foreign_keys(dbapi_connection: Any, _: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return Database(engine=engine, sessions=sessionmaker(engine, expire_on_commit=False))
