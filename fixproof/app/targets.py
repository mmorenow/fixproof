"""Per-product target specs: how to stand a product up and reach it.

Adding a new product is just a new entry here plus a PoC template. Nothing in the
runner is product-specific, which is what keeps FixProof vendor-agnostic.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import config


@dataclass
class TargetSpec:
    image_repo: str                 # docker repo, e.g. "httpd"
    port: int                       # the app's HTTP port inside the container
    # host_path -> container_path mounts (read-only). Used for products that need
    # a deliberately vulnerable config; empty for products vulnerable by default.
    mounts: dict[str, str] = field(default_factory=dict)
    # Set for products with no official versioned image: the runner builds the
    # image locally from this Docker build context instead of pulling it, passing
    # the requested version as `build_arg`. Left None for pull-only products.
    build_context: str | None = None
    build_arg: str | None = None
    # Linux capabilities to add back on top of --cap-drop ALL. Only what a product
    # genuinely needs: httpd binds port 80, which needs NET_BIND_SERVICE. Products
    # on high ports (grafana 3000, mlflow 5000) need nothing, so this stays empty.
    cap_add: list[str] = field(default_factory=list)


TARGETS: dict[str, TargetSpec] = {
    "httpd": TargetSpec(
        image_repo="httpd",
        port=80,
        mounts={
            str(config.TARGETS_DIR / "httpd-cve-2021-41773" / "httpd.conf"):
                "/usr/local/apache2/conf/httpd.conf",
        },
        cap_add=["NET_BIND_SERVICE"],  # bind port 80 after dropping all caps
    ),
    # Grafana's path traversal (CVE-2021-43798) needs no special config.
    "grafana": TargetSpec(image_repo="grafana/grafana", port=3000),
    # MLflow (CVE-2023-1177). No official versioned image exists, so these are
    # built locally from pip (see targets/mlflow/Dockerfile) — itself a sign that
    # harder targets cost more setup than pulling an official tag.
    "mlflow": TargetSpec(
        image_repo="fixproof-mlflow",
        port=5000,
        build_context=str(config.TARGETS_DIR / "mlflow"),
        build_arg="MLFLOW_VERSION",
    ),
}


def spec(product: str) -> TargetSpec:
    if product not in TARGETS:
        raise KeyError(f"unknown product: {product}")
    return TARGETS[product]
