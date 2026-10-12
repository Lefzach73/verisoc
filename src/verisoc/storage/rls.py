"""Fail-closed database readiness for the authenticated research service."""

from sqlalchemy import Engine, text

from verisoc.storage.models import metadata


def assert_rls(engine: Engine) -> None:
    with engine.connect() as conn:
        role = conn.execute(
            text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user")
        ).one()
        if role.rolsuper or role.rolbypassrls:
            raise ValueError("Restricted non-owner role required")
        rows = (
            conn.execute(
                text("""
            SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
                   pg_has_role(current_user, c.relowner, 'MEMBER') AS owner_access,
                   has_table_privilege(current_user, c.oid, 'TRUNCATE') AS truncate_access,
                   (SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid) AS policies
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relkind='r'
        """)
            )
            .mappings()
            .all()
        )
        by_name = {str(row["relname"]): row for row in rows}
        for name in metadata.tables:
            row = by_name.get(name)
            if (
                not row
                or not row["relrowsecurity"]
                or not row["relforcerowsecurity"]
                or row["owner_access"]
                or row["truncate_access"]
                or row["policies"] != 1
            ):
                raise ValueError("Missing or unsafe row-level security")

            policies = (
                conn.execute(
                    text("""
                SELECT p.polname, p.polcmd, p.polpermissive,
                       pg_get_expr(p.polqual,p.polrelid) AS read_expr,
                       pg_get_expr(p.polwithcheck,p.polrelid) AS write_expr
                FROM pg_policy p JOIN pg_class c ON p.polrelid=c.oid
                JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND c.relname=:name
            """),
                    {"name": name},
                )
                .mappings()
                .one()
            )
            expected = (
                "(tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), "
                "''::text))::uuid)"
            )
            if (
                policies["polname"] != "tenant_scope"
                or policies["polcmd"] != "*"
                or not policies["polpermissive"]
                or policies["read_expr"] != expected
                or policies["write_expr"] != expected
            ):
                raise ValueError("Unsafe row-level security policy expression")
            if (
                name != "reports"
                and conn.execute(
                    text(
                        "SELECT has_table_privilege(current_user,:name,'UPDATE') OR "
                        "has_table_privilege(current_user,:name,'DELETE')"
                    ),
                    {"name": name},
                ).scalar_one()
            ):
                raise ValueError("Immutable evidence table grants are unsafe")
