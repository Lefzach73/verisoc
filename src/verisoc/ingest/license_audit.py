from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlparse

import httpx
import yaml
from pydantic import Field

from verisoc.core.models import Digest, Frozen, Text
from verisoc.core.provenance import digest


class DatasetManifest(Frozen):
    schema_version: Literal["1.0"]
    dataset_id: Text
    source_url: Annotated[str, Field(max_length=2048)]
    source_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    sha256: Digest
    license_spdx: Literal["MIT", "Apache-2.0", "CC-BY-4.0", "CC0-1.0", "GPL-3.0-only"]
    license_url: Annotated[str, Field(min_length=1, max_length=2048)]
    attribution: Text
    audit_status: Literal["pending", "approved", "rejected"]
    reviewer: Annotated[str, Field(max_length=256)] = ""
    reviewed_on: Annotated[str, Field(max_length=32)] = ""
    discrepancy: bool = False
    resolution_evidence: Annotated[str, Field(max_length=2048)] = ""
    format: Literal["verisoc-jsonl-v1"] = "verisoc-jsonl-v1"
    max_bytes: Annotated[int, Field(ge=1, le=1048576)] = 1048576


def audit_manifest(path: Path) -> DatasetManifest:
    manifest = DatasetManifest.model_validate(yaml.safe_load(path.read_text()))
    parsed = urlparse(manifest.source_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("HTTPS source without credentials required")
    if manifest.audit_status != "approved" or not manifest.reviewer or not manifest.reviewed_on:
        raise ValueError("Exact dataset license audit has not been approved")
    if manifest.discrepancy and not manifest.resolution_evidence:
        raise ValueError("Unresolved license discrepancy")
    return manifest


def fetch(
    manifest_path: Path,
    destination: Path,
    *,
    accept_license: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> Path:
    # This explicit offline CLI workflow is never registered as an investigation tool.
    if not accept_license:
        raise ValueError("Explicit --accept-license required")
    manifest = audit_manifest(manifest_path)
    if destination.exists():
        raise FileExistsError("Refusing to overwrite dataset")
    # Only small audited defensive JSONL. Archive extraction and payload execution are absent.
    data = bytearray()
    with httpx.Client(
        timeout=30, follow_redirects=False, trust_env=False, transport=transport
    ) as client:
        with client.stream("GET", manifest.source_url) as response:
            response.raise_for_status()
            if response.status_code != 200:
                raise ValueError("Redirect/non-success response refused")
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > manifest.max_bytes:
                    raise ValueError("Dataset size limit exceeded")
    if digest(bytes(data)) != manifest.sha256:
        raise ValueError("Dataset checksum mismatch")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as handle:
        handle.write(data)
    return destination
