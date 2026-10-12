"""Provider wire schema. Runtime Pydantic validation remains authoritative."""

from copy import deepcopy
from typing import Any

from verisoc.verification.predicates import ALLOWED_ARGS


def strict_wire_schema(schema: dict[str, Any]) -> dict[str, Any]:
    def convert(value: Any) -> Any:
        if isinstance(value, list):
            return [convert(item) for item in value]
        if not isinstance(value, dict):
            return value
        result = {
            k: convert(v)
            for k, v in value.items()
            if k
            not in {
                "default",
                "format",
                "minimum",
                "maximum",
                "minItems",
                "maxItems",
                "minLength",
                "maxLength",
                "pattern",
                "title",
            }
        }
        if result.get("format") == "ipvanyaddress":
            # Pydantic's extension is not accepted by hosted JSON Schema subsets.
            # The local IPvAnyAddress validator still rejects invalid addresses.
            result.pop("format")
        if result.get("type") == "object":
            result["additionalProperties"] = False
            result["required"] = list(result.get("properties", {}))
        return result

    converted: dict[str, Any] = convert(schema)
    definitions = converted.get("$defs", {})
    if "CandidateClaim" in definitions and "PredicateArgs" in definitions:
        claim = definitions["CandidateClaim"]
        arguments = definitions["PredicateArgs"]["properties"]
        variants = []
        for kind, allowed in ALLOWED_ARGS.items():
            branch = deepcopy(claim)
            branch["properties"]["claim_kind"] = {"type": "string", "enum": [kind]}
            if allowed:
                branch["properties"]["parameters"] = {
                    "type": "object",
                    "properties": {name: deepcopy(arguments[name]) for name in sorted(allowed)},
                    "required": sorted(allowed),
                    "additionalProperties": False,
                }
            else:
                # These predicates take no arguments; avoid ambiguous empty provider objects.
                branch["properties"].pop("parameters")
                branch["required"].remove("parameters")
            variants.append(branch)
        definitions["CandidateClaim"] = {"anyOf": variants}
        del definitions["PredicateArgs"]
    return converted


def constrain_claim_ids(schema: dict[str, Any], pool: list[str]) -> None:
    """Constrain only proposal identities, never supply verification decisions."""
    claim = schema.get("$defs", {}).get("CandidateClaim", {})
    schema["$defs"]["ProposalIdentity"] = {"type": "string", "enum": pool}
    for variant in claim.get("anyOf", [claim]):
        variant["properties"]["claim_id"] = {"$ref": "#/$defs/ProposalIdentity"}
