"""Runtime configuration, read from the environment."""
from __future__ import annotations

import os
from pathlib import Path

# fixproof/ package root (…/fixproof)
ROOT = Path(__file__).resolve().parent.parent

DATABASE_URL = os.environ.get(
    "FIXPROOF_DATABASE_URL",
    "postgresql://fixproof:fixproof@localhost:55432/fixproof",
)

# Docker image names.
NUCLEI_IMAGE = os.environ.get("FIXPROOF_NUCLEI_IMAGE", "projectdiscovery/nuclei:latest")
READINESS_IMAGE = os.environ.get("FIXPROOF_READINESS_IMAGE", "busybox:latest")

# Isolated, egress-less Docker network that targets and the nuclei runner share.
# Created with --internal, so nothing on it can reach the internet.
RUN_NETWORK = os.environ.get("FIXPROOF_RUN_NETWORK", "fixproof-run")

# Where templates and target configs live.
REPLAYS_DIR = ROOT / "replays"
TARGETS_DIR = ROOT / "targets"

# Per-run limits.
TARGET_READY_TIMEOUT_S = int(os.environ.get("FIXPROOF_TARGET_READY_TIMEOUT_S", "30"))
NUCLEI_TIMEOUT_S = int(os.environ.get("FIXPROOF_NUCLEI_TIMEOUT_S", "60"))
