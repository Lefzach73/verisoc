"""Independent raw-file oracle for context: no producer, policy or verifier imports."""

import json
from datetime import datetime

from verisoc.core.ids import stable_id
from verisoc.core.models import Case
from verisoc.core.provenance import digest, json_hash
from verisoc.evaluation.fact_oracle import RawFactOracle
from verisoc.evidence.models import FactCandidate
from verisoc.v05.context_models import ActivityRecord, ContextBundle, ContextCandidate


class ContextOracle(RawFactOracle):
    def supports_context(
        self, case: Case, fact: FactCandidate, claim: ContextCandidate, source: ContextBundle
    ) -> bool:
        if not self.supports_fact(case, fact):
            return False
        body = claim.model_dump(mode="json", exclude={"fact_id", "verification_status"})
        if claim.fact_id != stable_id("verified-context", json_hash(body)):
            return False
        authority = source.authority
        if (
            authority.tenant_id != case.tenant_id
            or authority.dataset_id != case.dataset_id
            or digest(source.content) != authority.file_sha256
            or claim.tenant_id != case.tenant_id
            or claim.case_id != case.case_id
            or claim.dataset_id != case.dataset_id
            or claim.explained_fact_id != fact.fact_id
            or claim.source_id != authority.source_id
            or claim.event_proofs != fact.evidence_hashes
        ):
            return False
        try:
            lines = source.content.splitlines()
            index = claim.source_proof.row_index
            record = ActivityRecord.model_validate(json.loads(lines[index - 1]))
            row_hash = json_hash(record.model_dump(mode="json"))
            expected_id = stable_id(
                "activity",
                case.tenant_id,
                case.dataset_id,
                authority.source_id,
                authority.file_sha256,
                index,
                row_hash,
            )
            proof = claim.source_proof
            if (
                claim.activity != record
                or record.status != "approved"
                or record.dataset_id != case.dataset_id
                or proof.file_sha256 != authority.file_sha256
                or proof.raw_row_sha256 != row_hash
                or proof.context_record_id != expected_id
            ):
                return False
            if any(
                json.loads(line).get("ticket_id") == record.ticket_id
                and json.loads(line).get("status") == "revoked"
                for line in lines
            ):
                return False
            allowed = {
                "approved_password_reset": {"failed_login_burst", "success_after_failures"},
                "approved_lab_execution": {"windows_image_match"},
            }
            if fact.predicate not in allowed[record.kind]:
                return False
            if not set(fact.source_event_ids) <= {b.event_id for b in record.bindings}:
                return False
            for binding in record.bindings:
                original = self.records.get(binding.event_id)
                if (
                    original is None
                    or original.tenant != case.tenant_id
                    or original.dataset != case.dataset_id
                ):
                    return False
                raw = original.raw
                expected_code = (
                    (4624, 4625) if record.kind == "approved_password_reset" else (4688,)
                )
                if (
                    raw.event_code not in expected_code
                    or self.identity(raw.host, case.tenant_id) != record.host_id
                    or self.identity(raw.user, case.tenant_id) != record.principal_id
                    or not case.start_at <= raw.timestamp <= case.end_at
                    or not record.valid_from <= raw.timestamp <= record.valid_until
                    or self.proofs[binding.event_id].file_sha256 != record.event_source_sha256
                    or self.proofs[binding.event_id].canonical_sha256 != binding.canonical_sha256
                ):
                    return False
            # The source model enforces ordered aware timestamps; compare JSON origin as well.
            return datetime.fromisoformat(record.approved_at.isoformat()) <= record.valid_from
        except (ValueError, KeyError, IndexError, TypeError):
            return False
