"""Start and stop the pilot's AIGov Core. A thin wrapper over the SDK launcher (``aigov_py.trusted.launch``).

The SDK starts and stops Core. This wrapper adds what only a repository checkout has: building Core's image from
``rust/Dockerfile`` when it is missing. Resources carry the pilot's fixed prefix, ``aigov-pilot``, so ``stop`` removes
only the pilot's resources.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from aigov_py.trusted.launch import Running
from aigov_py.trusted.launch import start_binary as _sdk_start_binary
from aigov_py.trusted.launch import start_docker as _sdk_start_docker
from aigov_py.trusted.launch import stop as _sdk_stop

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from pilot_config import generate

PREFIX = "aigov-pilot"
DEFAULT_PORT = 18188
DEFAULT_IMAGE = "aigov-core:pilot"
REPO_ROOT = HERE.parents[1]

__all__ = [
    "DEFAULT_IMAGE",
    "DEFAULT_PORT",
    "PREFIX",
    "Running",
    "start_binary",
    "start_docker",
    "stop",
]


def _image_exists(image: str) -> bool:
    return (
        subprocess.run(
            ["docker", "image", "inspect", image], capture_output=True, check=False
        ).returncode
        == 0
    )


def start_docker(state_dir: Path, port: int, image: str) -> Running:
    if not _image_exists(image):
        print(
            f"building {image} from {REPO_ROOT} (first run only; this takes several minutes) ...",
            flush=True,
        )
        subprocess.run(["docker", "build", "-t", image, str(REPO_ROOT)], check=True)
    return _sdk_start_docker(state_dir, port, image, prefix=PREFIX, generate=generate)


def start_binary(
    state_dir: Path, port: int, binary: Path, database_url: str
) -> Running:
    return _sdk_start_binary(
        state_dir, port, binary, database_url, prefix=PREFIX, generate=generate
    )


def stop(state_dir: Path) -> list[str]:
    return _sdk_stop(state_dir, prefix=PREFIX)
