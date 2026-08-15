from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
import hashlib
import json


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "LAN_Router_Comms.ps1"
TEST = ROOT / "tests" / "Test-RuntimeIdentityContract.ps1"
VERSION_PATH = ROOT / "VERSION.txt"
METADATA_PATH = ROOT / "PACKAGE_METADATA.json"
MANIFEST_PATH = ROOT / "MANIFEST.json"
HASH_MODE = "sha256_text_utf8_lf_v1"
MANAGED_FILES = (
    "GatewayLANLink.bat",
    "Verify-Release.ps1",
    "LAN_Router_Comms.ps1",
    "VERSION.txt",
    "PACKAGE_METADATA.json",
)


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one source match, found {count}")
    return text.replace(old, new, 1)


def patch_engine() -> None:
    raw = SOURCE.read_bytes()
    had_bom = raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig")
    newline = "\r\n" if b"\r\n" in raw else "\n"
    root_line = "$script:Root = [IO.Path]::GetFullPath((Split-Path -Parent $script:ScriptPath))"
    gate_marker = "$script:ReleaseVerifierPath = Join-Path $script:Root 'Verify-Release.ps1'"
    gate = newline.join(
        (
            gate_marker,
            "if (-not (Test-Path -LiteralPath $script:ReleaseVerifierPath -PathType Leaf)) {",
            "    throw 'Gateway LAN Link release verifier is missing. Replace this folder with one complete checksum-verified package.'",
            "}",
            "& powershell.exe -NoLogo -NoProfile -File $script:ReleaseVerifierPath -Quiet",
            "if ($LASTEXITCODE -ne 0) {",
            "    throw 'Gateway LAN Link release identity or managed-file verification failed. Authenticated startup is blocked.'",
            "}",
        )
    )
    if gate_marker not in text:
        text = replace_once(text, root_line, root_line + newline + gate, "engine release gate")
    elif text.count(gate_marker) != 1:
        raise RuntimeError("The engine release gate marker appears more than once.")
    SOURCE.write_bytes((b"\xef\xbb\xbf" if had_bom else b"") + text.encode("utf-8"))


def patch_test() -> None:
    text = TEST.read_text(encoding="utf-8-sig")
    old = "$core = Get-Content -LiteralPath $corePath -Raw\n"
    new = (
        old
        + "$engineGatePosition = $core.IndexOf('Verify-Release.ps1', [StringComparison]::OrdinalIgnoreCase)\n"
        + "$engineFolderInitPosition = $core.IndexOf('function Initialize-AppFolders', [StringComparison]::OrdinalIgnoreCase)\n"
        + "Assert-True ($engineGatePosition -ge 0) 'The PowerShell engine does not invoke the release verifier.'\n"
        + "Assert-True ($engineFolderInitPosition -gt $engineGatePosition) 'The engine release gate must appear before runtime folder initialization.'\n"
        + "Assert-True ($core -match '\\$LASTEXITCODE\\s+-ne\\s+0') 'The PowerShell engine must stop after verifier failure.'\n"
    )
    if "$engineGatePosition = $core.IndexOf('Verify-Release.ps1'" not in text:
        text = replace_once(text, old, new, "engine gate test")
    TEST.write_text(text, encoding="utf-8", newline="\n")


def version_contract() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in VERSION_PATH.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def canonical_text_bytes(path: Path) -> bytes:
    text = path.read_bytes().decode("utf-8-sig")
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def regenerate_manifest() -> None:
    version = version_contract()
    metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8-sig"))
    for key in ("package_id", "version", "build_id", "parameter_baseline"):
        if str(metadata.get(key, "")) != version.get(key, ""):
            raise RuntimeError(f"VERSION.txt and PACKAGE_METADATA.json disagree on {key}")

    entries: list[OrderedDict[str, object]] = []
    total_bytes = 0
    for relative in sorted(MANAGED_FILES, key=str.casefold):
        path = ROOT / relative
        canonical = canonical_text_bytes(path)
        total_bytes += len(canonical)
        entries.append(
            OrderedDict(
                (
                    ("path", relative),
                    ("hash_mode", HASH_MODE),
                    ("size", len(canonical)),
                    ("sha256", hashlib.sha256(canonical).hexdigest()),
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
            ("manifest_scope", "runtime managed UTF-8 text normalized to LF; MANIFEST.json is the index and is not self-hashed"),
            ("hash_mode", HASH_MODE),
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
    patch_engine()
    patch_test()
    regenerate_manifest()


if __name__ == "__main__":
    main()
