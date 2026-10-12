"""Explicit ephemeral local PostgreSQL test cluster; no services/controller/provisioning."""

import os
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    if os.getenv("VERISOC_TEST_ADMIN_URL") and os.getenv("VERISOC_TEST_DATABASE_URL"):
        return subprocess.call(
            ["uv", "run", "--frozen", "--no-editable", "pytest", "-m", "postgres"], cwd=ROOT
        )
    pg_bin = os.getenv("VERISOC_PG_BIN", "/opt/homebrew/opt/postgresql@17/bin")
    initdb = shutil.which("initdb") or str(Path(pg_bin) / "initdb")
    pg_ctl = shutil.which("pg_ctl") or str(Path(pg_bin) / "pg_ctl")
    if not Path(initdb).exists():
        print("NOT RUN: local PostgreSQL binaries unavailable. Set VERISOC_PG_BIN or test URLs.")
        return 2
    with tempfile.TemporaryDirectory(prefix="verisoc-pg-") as temporary:
        cluster = Path(temporary) / "data"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        subprocess.run(
            [
                initdb,
                "-D",
                str(cluster),
                "-U",
                "verisoc_admin",
                "-A",
                "trust",
                "--no-locale",
                "-E",
                "UTF8",
            ],
            check=True,
            capture_output=True,
        )
        # Trust is confined to this ephemeral loopback-only synthetic test instance.
        subprocess.run(
            [
                pg_ctl,
                "-D",
                str(cluster),
                "-l",
                str(Path(temporary) / "server.log"),
                "-o",
                f"-h 127.0.0.1 -p {port} -k {temporary}",
                "-w",
                "start",
            ],
            check=True,
            capture_output=True,
        )
        try:
            admin_url = f"postgresql://verisoc_admin@127.0.0.1:{port}/postgres"
            with psycopg.connect(admin_url, autocommit=True) as conn:
                conn.execute((ROOT / "migrations/001_initial.sql").read_text())
                conn.execute("CREATE ROLE verisoc_app LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT")
                conn.execute("GRANT USAGE ON SCHEMA public TO verisoc_app")
                conn.execute("GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO verisoc_app")
                conn.execute("GRANT UPDATE ON reports TO verisoc_app")
            env = dict(
                os.environ,
                VERISOC_TEST_ADMIN_URL=admin_url,
                VERISOC_TEST_DATABASE_URL=f"postgresql+psycopg://verisoc_app@127.0.0.1:{port}/postgres",
            )
            return subprocess.call(
                ["uv", "run", "--frozen", "--no-editable", "pytest", "-m", "postgres"],
                cwd=ROOT,
                env=env,
            )
        finally:
            subprocess.run(
                [pg_ctl, "-D", str(cluster), "-m", "fast", "-w", "stop"],
                check=True,
                capture_output=True,
            )


if __name__ == "__main__":
    raise SystemExit(main())
