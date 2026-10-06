"""The execution core: stand up a target version, replay a PoC against it in an
isolated container, and report whether the state oracle matched.

Everything runs via the `docker` CLI as a subprocess so the steps are transparent
and easy to audit. Targets and the nuclei runner share an `--internal` Docker
network, so neither can reach the internet while a reporter-supplied PoC runs.
Stronger sandboxing (gVisor, cap-drop) comes in Phase 2; the no-egress network is
the guardrail that matters now.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import config


class DockerError(RuntimeError):
    pass


def _docker(*args: str, timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise DockerError(f"docker {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc


def ensure_image(image: str) -> None:
    """Pull an image if it is not already local. Pull happens over the host network
    before any container attaches to the internal network."""
    if _docker("image", "inspect", image, check=False).returncode == 0:
        return
    _docker("pull", image, timeout=600)


def ensure_network() -> None:
    net = config.RUN_NETWORK
    if _docker("network", "inspect", net, check=False).returncode == 0:
        return
    # --internal => no route to the host or the internet.
    _docker("network", "create", "--internal", net)


@dataclass
class ReplayResult:
    outcome: str            # pass | fail | error
    matched: bool | None    # did the oracle match?
    evidence: dict
    duration_ms: int


def _wait_ready(target: str) -> bool:
    """Poll the target over the internal network until httpd answers."""
    deadline = time.monotonic() + config.TARGET_READY_TIMEOUT_S
    last = ""
    while time.monotonic() < deadline:
        proc = _docker(
            "run", "--rm", "--network", config.RUN_NETWORK,
            config.READINESS_IMAGE,
            "wget", "-q", "-T", "2", "-O", "-", f"http://{target}/",
            check=False, timeout=15,
        )
        if proc.returncode == 0:
            return True
        last = proc.stderr.strip()
        time.sleep(1)
    raise DockerError(f"target {target} not ready within timeout: {last}")


def run_replay(product: str, version: str, template_path: Path) -> ReplayResult:
    """Run one template against one version. Starts a fresh target, probes it,
    runs nuclei on the same egress-less network, parses the oracle result, and
    always tears the target down."""
    ensure_network()
    image = f"{product}:{version}"
    ensure_image(image)
    ensure_image(config.NUCLEI_IMAGE)
    ensure_image(config.READINESS_IMAGE)

    run_id = uuid.uuid4().hex[:12]
    target = f"fixproof-target-{run_id}"
    conf = config.TARGETS_DIR / "httpd-cve-2021-41773" / "httpd.conf"
    started = time.monotonic()

    try:
        _docker(
            "run", "-d", "--name", target,
            "--network", config.RUN_NETWORK, "--network-alias", target,
            "--security-opt", "no-new-privileges",
            "--pids-limit", "256", "--memory", "512m",
            "-v", f"{conf}:/usr/local/apache2/conf/httpd.conf:ro",
            image,
        )
        _wait_ready(target)

        with tempfile.TemporaryDirectory() as outdir:
            out = Path(outdir)
            # The nuclei container runs as a different uid, so it must be able to
            # read the template and write the result inside this host-mounted dir.
            (out / "template.yaml").write_text(template_path.read_text())
            out.chmod(0o777)
            (out / "template.yaml").chmod(0o666)

            proc = _docker(
                "run", "--rm", "--network", config.RUN_NETWORK,
                "-v", f"{out}:/out",
                config.NUCLEI_IMAGE,
                "-u", f"http://{target}:80",
                "-t", "/out/template.yaml",
                "-jsonl", "-o", "/out/result.jsonl",
                "-disable-update-check", "-no-interactsh", "-silent",
                check=False, timeout=config.NUCLEI_TIMEOUT_S + 15,
            )
            result_file = out / "result.jsonl"
            matched = result_file.exists() and result_file.stat().st_size > 0
            evidence: dict = {"nuclei_stderr": proc.stderr.strip()[:2000]}
            if matched:
                lines = [l for l in result_file.read_text().splitlines() if l.strip()]
                evidence["findings"] = [json.loads(l) for l in lines]
    except DockerError as exc:
        return ReplayResult(
            outcome="error",
            matched=None,
            evidence={"error": str(exc)},
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    finally:
        _docker("rm", "-f", target, check=False)

    return ReplayResult(
        outcome="pass" if matched else "fail",
        matched=matched,
        evidence=evidence,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
