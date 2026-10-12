from typing import Any

from sqlalchemy import JSON, Column, Integer, MetaData, String, Table, Uuid

metadata = MetaData()


def table(name: str, *columns: Column[Any]) -> Table:
    return Table(
        name, metadata, Column("tenant_id", Uuid(as_uuid=False), primary_key=True), *columns
    )


datasets = table(
    "datasets",
    Column("dataset_id", String(256), primary_key=True),
    Column("file_sha256", String(64), nullable=False),
)
events = table(
    "events",
    Column("event_id", String(36), primary_key=True),
    Column("dataset_id", String(256), nullable=False, index=True),
    Column("occurred_at", String(40), nullable=False, index=True),
    Column("data", JSON, nullable=False),
)
source_records = table(
    "source_records",
    Column("dataset_id", String(256), primary_key=True),
    Column("file_sha256", String(64), primary_key=True),
    Column("row_index", Integer, primary_key=True),
    Column("raw_row_sha256", String(64), nullable=False),
    Column("event_id", String(36), nullable=False),
)
cases = table(
    "cases",
    Column("case_id", String(36), primary_key=True),
    Column("dataset_id", String(256), nullable=False),
    Column("data", JSON, nullable=False),
)
reports = table(
    "reports", Column("case_id", String(36), primary_key=True), Column("data", JSON, nullable=False)
)
audit = table(
    "audit", Column("audit_id", String(36), primary_key=True), Column("data", JSON, nullable=False)
)
