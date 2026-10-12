"""Check the included original-source hashes in the clean public companion."""

import hashlib
import json
import subprocess
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "PUBLIC_EXPORT_MANIFEST.json").read_text())
    files = manifest["files"]
    if not files or not manifest["source_commit"]:
        raise SystemExit("Empty export provenance")
    seen: set[str] = set()
    count = 0
    for item in files:
        if item["action"] == "omitted":
            continue
        name = item["public_path"]
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or name in seen:
            raise SystemExit("Invalid or duplicate export path")
        seen.add(name)
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"Missing exported file: {name}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != item["public_sha256"]:
            raise SystemExit(f"Export hash mismatch: {name}")
        if item["action"] in {"copied", "relocated"} and actual != item["source_sha256"]:
            raise SystemExit(f"Original source mismatch: {name}")
        count += 1
    for folder in ("src", "tests", "fixtures"):
        actual_names = {
            str(p.relative_to(root))
            for p in (root / folder).rglob("*")
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
        }
        expected = {name for name in seen if name.startswith(folder + "/")}
        if not actual_names or actual_names != expected:
            raise SystemExit(f"Export inventory mismatch: {folder}")
    public_files = manifest.get("public_files")
    if not public_files:
        raise SystemExit("Missing complete public inventory")
    for name, expected_hash in public_files.items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit("Invalid public inventory path")
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"Missing public file: {name}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
            raise SystemExit(f"Public file hash mismatch: {name}")
    # Avoid inspecting an unrelated enclosing checkout before this export is initialized.
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], cwd=root, text=True, capture_output=True
    )
    if result.returncode == 0 and Path(result.stdout.strip()).resolve() == root:
        tracked = set(
            subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
            .decode()
            .strip("\0")
            .split("\0")
        )
        expected_names = set(public_files) | {"PUBLIC_EXPORT_MANIFEST.json"}
        if tracked != expected_names:
            raise SystemExit("Tracked files differ from the complete public inventory")
    print(f"Public export PASS: {count} included original files; source inventory {len(files)}")


if __name__ == "__main__":
    main()
