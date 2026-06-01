"""Shared test fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

# Test vectors live in the ink repo root. Resolve relative so the tests
# work whether the package is installed or run in-place.
VECTORS_DIR = Path(__file__).resolve().parents[3] / "test-vectors"


def _load_vector(name: str) -> dict[str, Any]:
    path = VECTORS_DIR / f"{name}.json"
    if not path.exists():
        pytest.skip(f"test vector file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def jcs_vectors() -> dict[str, Any]:
    return _load_vector("jcs")


@pytest.fixture(scope="session")
def signing_vectors() -> dict[str, Any]:
    return _load_vector("signing")
