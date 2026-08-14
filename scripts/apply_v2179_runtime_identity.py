from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
import hashlib
import json


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "LAN_Router_Comms.ps1"
VERSION_PATH = ROOT / "VERSION.txt"
METADATA_PATH = ROOT / "PACKAGE_METADATA.json"
MANIFEST_PATH = ROOT / "MANIFEST.json"
BUILD_ID = "GLL-2.3.0-P2179-20260814"
MANAGED_FILES = (
    "GatewayLANLink.bat",
    "Verify-Release.ps1",
    "LAN_Router_Comms.ps1",
    "VERSION.txt",
    "PACKAGE_METADATA.json",
)


def parse_version_contract() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in VERSION_PATH.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise RuntimeError(f"Invalid VERSION.txt line: {raw_line}")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or key in values:
            raise RuntimeError(f"Invalid or duplicate VERSION.txt key: {key!r}")
        values[key] = value
    for required in (
        "package_id",
        "version",
        "build_id",
        "parameter_baseline",
        "canonical_entrypoint",
        "execution_namespace",
    ):
        if not values.get(required):
            raise RuntimeError(f"VERSION.txt is missing {required}")
    return values


def patch_source_build_id() -> None:
    raw = SOURCE.read_bytes()
    had_bom = raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig")
    newline = "\r\n" if b"\r\n" in raw else "\n"
    version_line = "$script:Version = '2.3.0'"
    build_line = f"$script:BuildId = '{BUILD_ID}'"
    if build_line in text:
        if text.count(build_line) != 1:
            raise RuntimeError("The expected build ID appears more than once in the source engine.")
    else:
        if text.count(version_line) != 1:
            raise RuntimeError("The source version line was not found exactly once.")
        text = text.replace(version_line, version_line + newline + build_line, 1)
    encoded = text.encode("utf-8")
    SOURCE.write_bytes((b"\xef\xbb\xbf" if had_bom else b"") + encoded)


def build_manifest() -> None:
    version = parse_version_contract()
    metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8-sig"))
    for key in ("package_id", "version", "build_id", "parameter_baseline"):
        if str(metadata.get(key, "")) != version[key]:
            raise RuntimeError(f"VERSION.txt and PACKAGE_METADATA.json disagree on {key}")
    if version["build_id"] != BUILD_ID:
        raise RuntimeError("The build ID constant does not match VERSION.txt.")

    entries: list[OrderedDict[str, object]] = []
    total_bytes = 0
    for relative in sorted(MANAGED_FILES, key=str.casefold):
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"Managed file is missing: {relative}")
        data = path.read_bytes()
        total_bytes += len(data)
        entries.append(
            OrderedDict(
                (
                    ("path", relative),
                    ("size", len(data)),
                    ("sha256", hashlib.sha256(data).hexdigest()),
                )
            )
        )

    manifest = OrderedDict(
        (
            ("schema", "GatewayLANLink.manifest.v1"),
            ("project", "Gateway LAN Link"),
            ("package_id", version["package_id"]),
            ("version", version["version"]),
            ("build_id", version["build_id"]),
            ("parameter_baseline", version["parameter_baseline"]),
            ("canonical_entrypoint", version["canonical_entrypoint"]),
            ("execution_namespace", version["execution_namespace"]),
            ("manifest_scope", "runtime managed files; MANIFEST.json is the signed index and is not self-hashed"),
            ("managed_file_count", len(entries)),
            ("managed_bytes", total_bytes),
            ("files", entries),
            ("rights_notice", "Copyright © 2026 Gateway Information Group LLC. All rights reserved."),
        )
    )
    MANIFEST_PATH.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> None:
    patch_source_build_id()
    build_manifest()


if __name__ == "__main__":
    main()
