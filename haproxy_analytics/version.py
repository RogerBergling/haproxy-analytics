"""Version and build metadata.

The container build supplies APP_VERSION, IMAGE_TAG, GIT_SHA, BUILD_DATE and
BUILD_NUMBER as environment variables. A local checkout can provide the same
values in public/version.json. Environment variables take precedence.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from . import __version__

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = PROJECT_ROOT / "public" / "version.json"

_DEFAULTS = {
    "version": __version__,
    "imageTag": "local",
    "commit": "local",
    "buildDate": None,
    "buildNumber": "local",
}

_ENV_MAP = {
    "APP_VERSION": "version",
    "IMAGE_TAG": "imageTag",
    "GIT_SHA": "commit",
    "BUILD_DATE": "buildDate",
    "BUILD_NUMBER": "buildNumber",
}


def version_info() -> dict[str, object]:
    """Return version/build metadata without ever reading secrets."""

    data: dict[str, object] = dict(_DEFAULTS)
    if VERSION_FILE.is_file():
        try:
            loaded = json.loads(VERSION_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            loaded = None
        if isinstance(loaded, dict):
            for key in _DEFAULTS:
                if key in loaded:
                    data[key] = loaded[key]
    for env_name, key in _ENV_MAP.items():
        value = os.environ.get(env_name, "").strip()
        if value:
            data[key] = value
    return data
