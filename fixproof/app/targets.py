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


TARGETS: dict[str, TargetSpec] = {
    "httpd": TargetSpec(
        image_repo="httpd",
        port=80,
        mounts={
            str(config.TARGETS_DIR / "httpd-cve-2021-41773" / "httpd.conf"):
                "/usr/local/apache2/conf/httpd.conf",
        },
    ),
    # Grafana's path traversal (CVE-2021-43798) needs no special config.
    "grafana": TargetSpec(image_repo="grafana/grafana", port=3000),
}


def spec(product: str) -> TargetSpec:
    if product not in TARGETS:
        raise KeyError(f"unknown product: {product}")
    return TARGETS[product]
