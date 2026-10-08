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

from . import config, targets


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


def _hardening_flags(cap_add: list[str] | None = None) -> list[str]:
    """Defense-in-depth flags applied to every container the engine spawns. The
    untrusted input is the reporter's PoC, which nuclei interprets, so each
    container starts from zero: no new privileges, all capabilities dropped (only
    a target's listed caps added back), and hard pid/memory caps so a PoC cannot
    exhaust the host. Combined with the egress-less network, a PoC can touch the
    target and nothing else. gVisor is layered on when FIXPROOF_RUNTIME is set."""
    flags = [
        "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL",
        "--pids-limit", config.PIDS_LIMIT,
        "--memory", config.MEMORY_LIMIT,
    ]
    for cap in cap_add or []:
        flags += ["--cap-add", cap]
    if config.RUNTIME:
        flags += ["--runtime", config.RUNTIME]
    return flags


def _image_present(image: str) -> bool:
    return _docker("image", "inspect", image, check=False).returncode == 0


def ensure_image(image: str) -> None:
    """Pull an image if it is not already local. Pull happens over the host network
    before any container attaches to the internal network."""
    if _image_present(image):
        return
    _docker("pull", image, timeout=600)


def ensure_target_image(spec: targets.TargetSpec, version: str) -> str:
    """Return a local image ref for one product version, building it if the product
    has no official image and pulling it otherwise. Either way the version is the
    image tag, so the isolated run itself never has to reach a registry. Build and
    pull both happen here, on the host network, before any attach to the internal
    one."""
    image = f"{spec.image_repo}:{version}"
    if spec.build_context is None:
        ensure_image(image)
        return image
    if _image_present(image):
        return image
    build_args: list[str] = []
    if spec.build_arg:
        build_args = ["--build-arg", f"{spec.build_arg}={version}"]
    _docker("build", "-t", image, *build_args, spec.build_context, timeout=1200)
    return image


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


def _wait_ready(target: str, port: int) -> bool:
    """Poll the target over the internal network until it answers on its port.
    A 2xx/3xx/4xx all prove the server is up; only a connection failure retries."""
    deadline = time.monotonic() + config.TARGET_READY_TIMEOUT_S
    last = ""
    while time.monotonic() < deadline:
        # Require a real HTTP response (exit 0). busybox wget follows redirects, so
        # a login redirect still counts as "up"; a connection refusal does not.
        proc = _docker(
            "run", "--rm", "--network", config.RUN_NETWORK,
            *_hardening_flags(),
            config.READINESS_IMAGE,
            "wget", "-q", "-T", "3", "-O", "/dev/null", f"http://{target}:{port}/",
            check=False, timeout=15,
        )
        if proc.returncode == 0:
            return True
        last = proc.stderr.strip()
        time.sleep(2)
    raise DockerError(f"target {target}:{port} not ready within timeout: {last}")


def run_replay(product: str, version: str, template_path: Path) -> ReplayResult:
    """Run one template against one version. Starts a fresh target, probes it,
    runs nuclei on the same egress-less network, parses the oracle result, and
    always tears the target down."""
    ensure_network()
    spec = targets.spec(product)
    image = ensure_target_image(spec, version)
    ensure_image(config.NUCLEI_IMAGE)
    ensure_image(config.READINESS_IMAGE)

    run_id = uuid.uuid4().hex[:12]
    target = f"fixproof-target-{run_id}"
    started = time.monotonic()

    mount_args: list[str] = []
    for host_path, container_path in spec.mounts.items():
        mount_args += ["-v", f"{host_path}:{container_path}:ro"]

    try:
        _docker(
            "run", "-d", "--name", target,
            "--network", config.RUN_NETWORK, "--network-alias", target,
            *_hardening_flags(spec.cap_add),
            *mount_args,
            image,
        )
        _wait_ready(target, spec.port)

        with tempfile.TemporaryDirectory() as outdir:
            out = Path(outdir)
            # The nuclei container runs as a different uid, so it must be able to
            # read the template and write the result inside this host-mounted dir.
            (out / "template.yaml").write_text(template_path.read_text())
            out.chmod(0o777)
            (out / "template.yaml").chmod(0o666)

            proc = _docker(
                "run", "--rm", "--network", config.RUN_NETWORK,
                *_hardening_flags(),
                "-v", f"{out}:/out",
                config.NUCLEI_IMAGE,
                "-u", f"http://{target}:{spec.port}",
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
