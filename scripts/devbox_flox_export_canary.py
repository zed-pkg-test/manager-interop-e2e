#!/usr/bin/env python3
"""Independent black-box certification for canonical Devbox/Flox export.

The harness treats both product binaries as untrusted processes. It invokes no
Devbox, Flox, Nix, package manager, registry, or network service.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Sequence


@dataclass
class CaseResult:
    name: str
    status: str
    duration_ms: int
    detail: str = ""


class CertificationFailure(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zed", required=True, type=Path)
    parser.add_argument("--staged", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    return parser.parse_args()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def assert_full_sha(value: str, field: str) -> None:
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise CertificationFailure(f"{field} must be a full lowercase 40-hex commit")


def isolated_env(work: Path) -> dict[str, str]:
    home = work / "home"
    empty_path = work / "empty-path"
    home.mkdir(parents=True, exist_ok=True)
    empty_path.mkdir(parents=True, exist_ok=True)

    preserved = [
        "SystemRoot",
        "SYSTEMROOT",
        "ComSpec",
        "COMSPEC",
        "PATHEXT",
        "WINDIR",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
    ]
    env = {name: os.environ[name] for name in preserved if name in os.environ}
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "ZED_PKG_HOME": str(home / ".zed-pkg"),
            "ZED_PKG_UPDATE_CHECK": "false",
            "PATH": str(empty_path),
            "NO_COLOR": "1",
            "CLICOLOR": "0",
            "RUST_BACKTRACE": "0",
            # An accidental HTTP client must fail locally rather than use an
            # ambient proxy or credentialed network path.
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "localhost,127.0.0.1",
        }
    )
    return env


def run(
    binary: Path,
    arguments: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    expect_success: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(binary), *arguments],
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if (result.returncode == 0) != expect_success:
        expectation = "success" if expect_success else "failure"
        raise CertificationFailure(
            f"expected {expectation}: {binary.name} {list(arguments)!r}; "
            f"exit={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def canonical_args(manager: str, extra: Sequence[str] = ()) -> list[str]:
    return ["env", "export", manager, *extra]


def staged_args(manager: str, extra: Sequence[str] = ()) -> list[str]:
    return [manager, *extra]


def write_plan(root: Path, platform_name: str) -> Path:
    plan_path = root / ".zed" / "environment-plan.json"
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan = {
        "schema": 1,
        "tools": {
            "node": {
                "requirement": "^22",
                "resolved": "22.11.0",
                "provider": "nixpkgs",
                "backend": "nodejs_22",
                "checksums": [
                    {"algorithm": "sha256", "value": "a" * 64}
                ],
                "platforms": [],
            }
        },
        "system-packages": {
            "git": {
                "requirement": "2.47.0",
                "resolved": "2.47.0",
                "provider": "nixpkgs",
                "package_ref": "gitFull",
                "checksums": [
                    {"algorithm": "sha256", "value": "b" * 64}
                ],
                "platforms": [platform_name],
            }
        },
        "platforms": [platform_name],
        "activation": "frozen-install",
        "sources": [],
    }
    plan_path.write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return plan_path


def manager_paths(manager: str) -> tuple[Path, Path]:
    if manager == "devbox":
        return Path("devbox.json"), Path(".zed/environment-exports/devbox.json")
    if manager == "flox":
        return Path(".flox/env/manifest.toml"), Path(".zed/environment-exports/flox.json")
    raise AssertionError(manager)


def parse_result(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CertificationFailure(
            f"result stdout is not one JSON document: {error}: {result.stdout!r}"
        ) from error
    if not isinstance(value, dict):
        raise CertificationFailure(f"result is not a JSON object: {value!r}")
    return value


def validate_receipt(
    root: Path,
    manager: str,
    plan_path: Path,
    output_relative: Path,
    receipt_relative: Path,
) -> dict[str, object]:
    output = (root / output_relative).read_bytes()
    receipt_bytes = (root / receipt_relative).read_bytes()
    try:
        receipt = json.loads(receipt_bytes)
    except json.JSONDecodeError as error:
        raise CertificationFailure(f"receipt is not JSON: {error}") from error

    expected = {
        "schema": "zed.environment-export-receipt/v1",
        "generator_schema": 1,
        "manager": manager,
        "plan_path": ".zed/environment-plan.json",
        "input_sha256": sha256_bytes(plan_path.read_bytes()),
        "output_path": output_relative.as_posix(),
        "output_sha256": sha256_bytes(output),
        "activation": "zed install --frozen",
        "native_lock_required": True,
    }
    for field, value in expected.items():
        if receipt.get(field) != value:
            raise CertificationFailure(
                f"receipt field {field!r} differs: {receipt.get(field)!r} != {value!r}"
            )
    plan_digest = receipt.get("environment_plan_sha256")
    if not isinstance(plan_digest, str) or len(plan_digest) != 64:
        raise CertificationFailure("receipt has no canonical environment-plan SHA-256")
    packages = receipt.get("packages")
    if not isinstance(packages, list) or len(packages) != 2:
        raise CertificationFailure(f"receipt package inventory drift: {packages!r}")
    for package in packages:
        provenance = package.get("provenance_sha256") if isinstance(package, dict) else None
        if not isinstance(provenance, str) or len(provenance) != 64:
            raise CertificationFailure(f"package provenance digest is invalid: {package!r}")
    return receipt


def validate_manager_output(root: Path, manager: str, output_relative: Path) -> None:
    output_path = root / output_relative
    if manager == "devbox":
        document = json.loads(output_path.read_text(encoding="utf-8"))
        if document.get("shell", {}).get("init_hook") != ["zed install --frozen"]:
            raise CertificationFailure(f"Devbox activation drift: {document!r}")
        packages = document.get("packages")
        expected = {
            "gitFull": {"version": "2.47.0", "platforms": ["x86_64-linux"]},
            "nodejs_22": {"version": "22.11.0"},
        }
        if packages != expected:
            raise CertificationFailure(f"Devbox package projection drift: {packages!r}")
    else:
        document = tomllib.loads(output_path.read_text(encoding="utf-8"))
        if document.get("version") != 1:
            raise CertificationFailure(f"Flox schema drift: {document!r}")
        if document.get("hook", {}).get("on-activate") != "zed install --frozen":
            raise CertificationFailure(f"Flox activation drift: {document!r}")
        if document.get("options", {}).get("systems") != ["aarch64-darwin"]:
            raise CertificationFailure(f"Flox platform projection drift: {document!r}")
        install = document.get("install", {})
        expected = {
            "git": {
                "pkg-path": "gitFull",
                "version": "2.47.0",
                "systems": ["aarch64-darwin"],
            },
            "node": {"pkg-path": "nodejs_22", "version": "22.11.0"},
        }
        if install != expected:
            raise CertificationFailure(f"Flox package projection drift: {install!r}")


def case_default_parity(
    zed: Path, staged: Path, workspace: Path, env: dict[str, str]
) -> None:
    for manager, platform_name in [
        ("devbox", "x86_64-linux"),
        ("flox", "aarch64-darwin"),
    ]:
        canonical_root = workspace / f"{manager}-canonical"
        staged_root = workspace / f"{manager}-staged"
        canonical_root.mkdir(parents=True)
        staged_root.mkdir(parents=True)
        canonical_plan = write_plan(canonical_root, platform_name)
        staged_plan = write_plan(staged_root, platform_name)

        canonical = run(
            zed,
            canonical_args(manager, ["--json"]),
            cwd=canonical_root,
            env=env,
        )
        compatibility = run(
            staged,
            staged_args(manager, ["--json"]),
            cwd=staged_root,
            env=env,
        )
        if canonical.stdout != compatibility.stdout or canonical.stderr != compatibility.stderr:
            raise CertificationFailure(
                f"{manager} canonical/staged result stream mismatch\n"
                f"canonical stdout={canonical.stdout!r}\nstaged stdout={compatibility.stdout!r}\n"
                f"canonical stderr={canonical.stderr!r}\nstaged stderr={compatibility.stderr!r}"
            )
        result = parse_result(canonical)
        if result.get("manager") != manager or result.get("changed") is not True:
            raise CertificationFailure(f"unexpected first export result: {result!r}")

        output_relative, receipt_relative = manager_paths(manager)
        canonical_output = (canonical_root / output_relative).read_bytes()
        staged_output = (staged_root / output_relative).read_bytes()
        canonical_receipt = (canonical_root / receipt_relative).read_bytes()
        staged_receipt = (staged_root / receipt_relative).read_bytes()
        if canonical_output != staged_output:
            raise CertificationFailure(f"{manager} canonical/staged output bytes differ")
        if canonical_receipt != staged_receipt:
            raise CertificationFailure(f"{manager} canonical/staged receipt bytes differ")
        validate_receipt(
            canonical_root,
            manager,
            canonical_plan,
            output_relative,
            receipt_relative,
        )
        validate_receipt(
            staged_root,
            manager,
            staged_plan,
            output_relative,
            receipt_relative,
        )
        validate_manager_output(canonical_root, manager, output_relative)


def case_idempotence(
    zed: Path, _staged: Path, workspace: Path, env: dict[str, str]
) -> None:
    for manager, platform_name in [
        ("devbox", "x86_64-linux"),
        ("flox", "aarch64-darwin"),
    ]:
        root = workspace / f"{manager}-idempotence"
        root.mkdir(parents=True)
        write_plan(root, platform_name)
        first = run(zed, canonical_args(manager, ["--json"]), cwd=root, env=env)
        first_result = parse_result(first)
        output_relative, receipt_relative = manager_paths(manager)
        output_before = (root / output_relative).read_bytes()
        receipt_before = (root / receipt_relative).read_bytes()

        second = run(zed, canonical_args(manager, ["--json"]), cwd=root, env=env)
        second_result = parse_result(second)
        if first_result.get("changed") is not True or second_result.get("changed") is not False:
            raise CertificationFailure(
                f"{manager} changed/idempotent contract drift: {first_result!r}, {second_result!r}"
            )
        if output_before != (root / output_relative).read_bytes():
            raise CertificationFailure(f"{manager} idempotent run rewrote output bytes")
        if receipt_before != (root / receipt_relative).read_bytes():
            raise CertificationFailure(f"{manager} idempotent run rewrote receipt bytes")
        if first_result.get("output_sha256") != sha256_bytes(output_before):
            raise CertificationFailure(f"{manager} result output digest drift")


def case_custom_paths_and_environment(
    zed: Path, staged: Path, workspace: Path, env: dict[str, str]
) -> None:
    canonical_root = workspace / "custom-canonical"
    staged_root = workspace / "custom-staged"
    env_root = workspace / "custom-env"
    for root in [canonical_root, staged_root, env_root]:
        root.mkdir(parents=True)
        write_plan(root, "x86_64-linux")

    canonical = run(
        zed,
        canonical_args(
            "devbox",
            [
                "--plan",
                ".zed/environment-plan.json",
                "--output",
                "generated/devbox.json",
                "--receipt",
                "generated/devbox.receipt.json",
                "--json",
            ],
        ),
        cwd=canonical_root,
        env=env,
    )
    compatibility = run(
        staged,
        staged_args(
            "devbox",
            [
                "--plan",
                ".zed/environment-plan.json",
                "--out",
                "generated/devbox.json",
                "--receipt",
                "generated/devbox.receipt.json",
                "--json",
            ],
        ),
        cwd=staged_root,
        env=env,
    )
    if canonical.stdout != compatibility.stdout:
        raise CertificationFailure("custom canonical/staged result JSON differs")
    for relative in [Path("generated/devbox.json"), Path("generated/devbox.receipt.json")]:
        if (canonical_root / relative).read_bytes() != (staged_root / relative).read_bytes():
            raise CertificationFailure(f"custom canonical/staged bytes differ: {relative}")

    env_override = dict(env)
    env_override.update(
        {
            "ZED_PKG_ENV_PLAN": ".zed/environment-plan.json",
            "ZED_PKG_ENV_OUTPUT": "generated/devbox.json",
            "ZED_PKG_ENV_RECEIPT": "generated/devbox.receipt.json",
            "ZED_PKG_ENV_JSON": "true",
        }
    )
    environment_result = run(
        zed,
        canonical_args("devbox"),
        cwd=env_root,
        env=env_override,
    )
    if canonical.stdout != environment_result.stdout:
        raise CertificationFailure("flags-to-environment result parity drift")
    for relative in [Path("generated/devbox.json"), Path("generated/devbox.receipt.json")]:
        if (canonical_root / relative).read_bytes() != (env_root / relative).read_bytes():
            raise CertificationFailure(f"flags-to-environment bytes differ: {relative}")


def case_conflicts_are_atomic(
    zed: Path, _staged: Path, workspace: Path, env: dict[str, str]
) -> None:
    output_conflict = workspace / "output-conflict"
    output_conflict.mkdir(parents=True)
    write_plan(output_conflict, "x86_64-linux")
    output_path, receipt_path = manager_paths("devbox")
    human_output = b'{"human_owned":true}\n'
    (output_conflict / output_path).write_bytes(human_output)
    result = run(
        zed,
        canonical_args("devbox", ["--json"]),
        cwd=output_conflict,
        env=env,
        expect_success=False,
    )
    if (output_conflict / output_path).read_bytes() != human_output:
        raise CertificationFailure("conflicting human output was modified")
    if (output_conflict / receipt_path).exists():
        raise CertificationFailure("output conflict still created a receipt")
    if "differs" not in (result.stdout + result.stderr).lower() and "conflict" not in (
        result.stdout + result.stderr
    ).lower():
        raise CertificationFailure(f"output conflict diagnostic is unclear: {result.stderr}")

    receipt_conflict = workspace / "receipt-conflict"
    receipt_conflict.mkdir(parents=True)
    write_plan(receipt_conflict, "x86_64-linux")
    (receipt_conflict / receipt_path).parent.mkdir(parents=True, exist_ok=True)
    human_receipt = b'{"human_owned":true}\n'
    (receipt_conflict / receipt_path).write_bytes(human_receipt)
    run(
        zed,
        canonical_args("devbox", ["--json"]),
        cwd=receipt_conflict,
        env=env,
        expect_success=False,
    )
    if (receipt_conflict / receipt_path).read_bytes() != human_receipt:
        raise CertificationFailure("conflicting human receipt was modified")
    if (receipt_conflict / output_path).exists():
        raise CertificationFailure("receipt conflict still created manager output")


def case_paths_and_managers_fail_closed(
    zed: Path, staged: Path, workspace: Path, env: dict[str, str]
) -> None:
    root = workspace / "negative"
    root.mkdir(parents=True)
    write_plan(root, "x86_64-linux")

    outside = workspace / "escape.json"
    result = run(
        zed,
        canonical_args(
            "devbox",
            [
                "--output",
                "../escape.json",
                "--receipt",
                "generated/receipt.json",
            ],
        ),
        cwd=root,
        env=env,
        expect_success=False,
    )
    if outside.exists():
        raise CertificationFailure("project-relative output validation allowed escape")
    if "project" not in (result.stdout + result.stderr).lower():
        raise CertificationFailure(f"path escape diagnostic is unclear: {result.stderr}")

    same_path = run(
        zed,
        canonical_args(
            "devbox",
            [
                "--output",
                "generated/same.json",
                "--receipt",
                "generated/same.json",
            ],
        ),
        cwd=root,
        env=env,
        expect_success=False,
    )
    if "different paths" not in (same_path.stdout + same_path.stderr).lower():
        raise CertificationFailure(f"same output/receipt diagnostic drift: {same_path.stderr}")

    devbox_check = run(
        zed,
        canonical_args("devbox", ["--check"]),
        cwd=root,
        env=env,
        expect_success=False,
    )
    if "supported only for mise" not in (devbox_check.stdout + devbox_check.stderr).lower():
        raise CertificationFailure(f"Devbox --check boundary drift: {devbox_check.stderr}")

    invalid_manager = run(
        zed,
        canonical_args("asdf"),
        cwd=root,
        env=env,
        expect_success=False,
    )
    if "invalid value" not in invalid_manager.stderr.lower():
        raise CertificationFailure(f"canonical invalid-manager boundary drift: {invalid_manager.stderr}")

    staged_invalid = run(
        staged,
        staged_args("mise"),
        cwd=root,
        env=env,
        expect_success=False,
    )
    if "invalid value" not in staged_invalid.stderr.lower():
        raise CertificationFailure(f"staged invalid-manager boundary drift: {staged_invalid.stderr}")


def case_flox_platform_fails_before_write(
    zed: Path, _staged: Path, workspace: Path, env: dict[str, str]
) -> None:
    root = workspace / "unsupported-flox-platform"
    root.mkdir(parents=True)
    write_plan(root, "x86_64-windows")
    output_relative, receipt_relative = manager_paths("flox")
    result = run(
        zed,
        canonical_args("flox", ["--json"]),
        cwd=root,
        env=env,
        expect_success=False,
    )
    if (root / output_relative).exists() or (root / receipt_relative).exists():
        raise CertificationFailure("unsupported Flox platform wrote partial state")
    if "platform" not in (result.stdout + result.stderr).lower():
        raise CertificationFailure(f"unsupported platform diagnostic drift: {result.stderr}")


def main() -> int:
    args = parse_args()
    candidate = args.candidate.lower()
    assert_full_sha(candidate, "candidate")
    zed = args.zed.resolve()
    staged = args.staged.resolve()
    if not zed.is_file() or not staged.is_file():
        raise SystemExit(f"missing product binaries: zed={zed}, staged={staged}")

    work = args.work.resolve()
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    env = isolated_env(work)
    workspace = work / "cases"
    workspace.mkdir()

    versions = {
        "zed": run(zed, ["--version"], cwd=workspace, env=env).stdout.strip(),
        "staged": run(staged, ["--version"], cwd=workspace, env=env).stdout.strip(),
    }
    cases: list[
        tuple[
            str,
            Callable[[Path, Path, Path, dict[str, str]], None],
        ]
    ] = [
        ("default-canonical-staged-parity", case_default_parity),
        ("deterministic-idempotence", case_idempotence),
        ("custom-path-and-env-parity", case_custom_paths_and_environment),
        ("atomic-conflict-refusal", case_conflicts_are_atomic),
        ("path-and-manager-boundaries", case_paths_and_managers_fail_closed),
        ("flox-platform-fail-closed", case_flox_platform_fails_before_write),
    ]

    results: list[CaseResult] = []
    failed = False
    for name, case in cases:
        started = time.monotonic()
        try:
            case(zed, staged, workspace, env)
            results.append(
                CaseResult(
                    name=name,
                    status="passed",
                    duration_ms=round((time.monotonic() - started) * 1000),
                )
            )
            print(f"PASS {name}")
        except Exception as error:  # retain complete bounded evidence
            failed = True
            results.append(
                CaseResult(
                    name=name,
                    status="failed",
                    duration_ms=round((time.monotonic() - started) * 1000),
                    detail=str(error),
                )
            )
            print(f"FAIL {name}: {error}", file=sys.stderr)

    evidence = {
        "schema": "zed-pkg-test/devbox-flox-export-canary/v1",
        "candidate": candidate,
        "status": "failed" if failed else "passed",
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "versions": versions,
        "claims": {
            "external_manager_invocation": False,
            "runtime_network_required": False,
            "persistent_credentials_required": False,
            "canonical_and_staged_share_observable_contract": True,
        },
        "results": [asdict(result) for result in results],
    }
    evidence_path = args.evidence.resolve()
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(f"wrote {evidence_path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
