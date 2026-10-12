"""Full authenticated v0.5 HTTP flow against the real restricted PostgreSQL role."""

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from test_postgres import pg as pg

from verisoc.api.auth import Auth
from verisoc.core.provenance import digest
from verisoc.evaluation.v05_raw_oracle import SingleTenantOracle
from verisoc.v05.api import create_app
from verisoc.v05.context_models import ActivityRecord, ContextAuthority, ContextBundle, EventBinding

pytestmark = pytest.mark.postgres


def test_authenticated_import_detection_context_and_tenant_isolation_over_http(pg):
    # Reuse the integration fixture's real migrated database and restricted role.
    # Dedicated tenants avoid changing the historical fixture's fixed record counts.
    tenant_a, tenant_b = uuid4(), uuid4()
    dataset = f"http-acceptance-{uuid4()}"
    start = datetime(2027, 9, 1, tzinfo=UTC)
    raw = (
        "\n".join(
            json.dumps(
                dict(
                    event_code=4625 if i < 6 else 4624,
                    timestamp=(start + timedelta(seconds=i * 10)).isoformat(),
                    host="synthetic-shared-host",
                    user="synthetic-shared-principal",
                )
            )
            for i in range(7)
        )
        + "\n"
    ).encode()
    oracle = SingleTenantOracle(raw, tenant_a, dataset)
    # Pin the server's synthetic context before any HTTP request. The independent
    # raw-file oracle supplies predicted IDs; actual imported DB proofs are checked below.
    approval = ActivityRecord(
        kind="approved_password_reset",
        status="approved",
        ticket_id="synthetic-http-acceptance-ticket",
        dataset_id=dataset,
        event_source_sha256=digest(raw),
        host_id=oracle.identity("synthetic-shared-host", tenant_a),
        principal_id=oracle.identity("synthetic-shared-principal", tenant_a),
        approved_at=start - timedelta(minutes=1),
        valid_from=start,
        valid_until=start + timedelta(minutes=5),
        bindings=tuple(
            EventBinding(event_id=p.event_id, canonical_sha256=p.canonical_sha256)
            for p in oracle.proofs.values()
        ),
    )
    context = (approval.model_dump_json() + "\n").encode()
    bundle = ContextBundle(
        content=context,
        authority=ContextAuthority(
            tenant_id=tenant_a,
            dataset_id=dataset,
            source_id="synthetic-server-context",
            file_sha256=digest(context),
            authorization_reference="Synthetic acceptance control; no human approval claim.",
        ),
    )
    key = "synthetic-http-e2e-signing-key-at-least-32-bytes"
    issued = datetime.now(UTC)

    def headers(tenant):
        return {
            "Authorization": "Bearer "
            + jwt.encode(
                dict(
                    sub="synthetic-http-acceptance",
                    tenant_id=str(tenant),
                    iss="verisoc-research",
                    aud="verisoc-api",
                    iat=issued,
                    nbf=issued,
                    exp=issued + timedelta(minutes=5),
                ),
                key,
                algorithm="HS256",
            )
        }

    with TestClient(create_app(pg, Auth(key), (bundle,))) as client:
        assert client.get("/v1/cases").status_code == 401
        cases = {}
        imports = {}
        for tenant in (tenant_a, tenant_b):
            auth = headers(tenant)
            response = client.post(
                "/v1/events/import",
                headers=auth,
                json={"dataset_id": dataset, "jsonl": raw.decode()},
            )
            assert response.status_code == 200, response.text
            imports[tenant] = response.json()
            assert imports[tenant]["accepted"] == 7
            assert imports[tenant]["tenant_id"] == str(tenant)
            assert imports[tenant]["mode"] == "AUTHENTICATED_POSTGRES_RLS"
            detected = client.post("/v1/cases/detect", headers=auth, json={"dataset_id": dataset})
            assert detected.status_code == 200, detected.text
            assert {c["alert"]["rule_id"] for c in detected.json()} == {
                "auth_burst",
                "auth_success_after_failures",
            }
            opened = client.post(
                "/v1/evidence/cases",
                headers=auth,
                json=dict(
                    dataset_id=dataset,
                    start_at=start.isoformat(),
                    end_at=(start + timedelta(seconds=60)).isoformat(),
                ),
            )
            assert opened.status_code == 200, opened.text
            cases[tenant] = opened.json()
            assert set(cases[tenant]["event_ids"]) == set(imports[tenant]["event_ids"])

        assert set(imports[tenant_a]["event_ids"]).isdisjoint(imports[tenant_b]["event_ids"])
        with pg.scope(tenant_a) as repo:
            for event_id in imports[tenant_a]["event_ids"]:
                actual = repo.get_event(UUID(event_id))
                assert repo.provenance_ok(actual)
                assert actual.canonical_sha256 == oracle.proofs[actual.event_id].canonical_sha256
                assert actual.source_ref.file_sha256 == digest(raw)

        cid_a, cid_b = cases[tenant_a]["case_id"], cases[tenant_b]["case_id"]
        reports = {}
        for tenant, cid in ((tenant_a, cid_a), (tenant_b, cid_b)):
            facts = client.get(f"/v1/cases/{cid}/facts", headers=headers(tenant))
            assert facts.status_code == 200, facts.text
            response = client.post(f"/v05/cases/{cid}/triage", headers=headers(tenant), json={})
            assert response.status_code == 200, response.text
            report = reports[tenant] = response.json()
            assert report["tenant_id"] == str(tenant)
            assert report["incident_verdict"] == "needs_review"
            assert len(report["verified_observations"]) == 7
            assert len(report["indicator_evidence"]) == 2
            assert {fact["predicate"] for fact in report["indicator_evidence"]} == {
                "failed_login_burst",
                "success_after_failures",
            }
            assert {
                event_id
                for fact in report["verified_observations"]
                for event_id in fact["source_event_ids"]
            } == set(imports[tenant]["event_ids"])

        assert reports[tenant_a]["disposition"] == "explained_activity"
        assert not reports[tenant_a]["triage_flag"]
        assert len(reports[tenant_a]["verified_context"]) == 2
        for fact in reports[tenant_a]["verified_context"]:
            assert fact["verification_status"] == "verified"
            assert fact["source_proof"]["file_sha256"] == digest(context)
            assert fact["source_proof"]["row_index"] == 1
            assert {p["event_id"] for p in fact["event_proofs"]} <= set(
                imports[tenant_a]["event_ids"]
            )
        assert reports[tenant_b]["triage_flag"]
        assert reports[tenant_b]["disposition"] == "suspicious"
        assert reports[tenant_b]["verified_context"] == []

        # A forged header cannot override the authenticated principal; foreign and
        # nonexistent case identifiers return the same concealed response.
        foreign_auth = dict(headers(tenant_b), **{"X-Tenant-ID": str(tenant_a)})
        for endpoint in ("/v1/cases/{}", "/v1/cases/{}/facts", "/v05/cases/{}/triage"):
            method = client.post if endpoint.startswith("/v05/") else client.get
            foreign = method(endpoint.format(cid_a), headers=foreign_auth)
            absent = method(endpoint.format(uuid4()), headers=foreign_auth)
            assert foreign.status_code == absent.status_code == 404
            assert foreign.json() == absent.json() == {"error": "not_found"}

        injected = client.post(
            f"/v05/cases/{cid_b}/triage",
            headers=headers(tenant_b),
            json={
                "tenant_id": str(tenant_a),
                "authority": bundle.authority.model_dump(mode="json"),
                "context": approval.model_dump(mode="json"),
            },
        )
        assert injected.status_code == 422
        assert injected.json() == {"error": "invalid_request"}
        after = client.post(f"/v05/cases/{cid_b}/triage", headers=headers(tenant_b), json={})
        assert after.status_code == 200
        assert after.json()["triage_flag"] and after.json()["verified_context"] == []
