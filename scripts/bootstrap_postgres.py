"""Explicit setup of disposable CI test DB; requires test admin URL, never runtime invoked."""

import os
from pathlib import Path

import psycopg

root = Path(__file__).resolve().parents[1]
with psycopg.connect(os.environ["VERISOC_TEST_ADMIN_URL"], autocommit=True) as connection:
    connection.execute((root / "migrations/001_initial.sql").read_text())
    connection.execute((root / "migrations/002_test_role.sql").read_text())
print("Disposable RLS test schema initialized")
