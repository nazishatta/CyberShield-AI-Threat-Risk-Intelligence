"""Loads config.yaml and overlays environment variables."""

import os
from functools import lru_cache
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv()

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def load_config(path: str | None = None) -> dict:
    cfg_path = Path(path) if path else _PROJECT_ROOT / "config.yaml"
    with open(cfg_path, "r") as fh:
        return yaml.safe_load(fh)


def project_root() -> Path:
    return _PROJECT_ROOT
