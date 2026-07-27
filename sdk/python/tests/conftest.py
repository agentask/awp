from __future__ import annotations

import json
from pathlib import Path

TESTDATA_DIR = Path(__file__).resolve().parents[3] / "testdata" / "awp-sig"


def load_vector(name: str) -> dict:
    with open(TESTDATA_DIR / f"{name}.json", "rb") as f:
        return json.load(f)


def all_vector_names() -> list[str]:
    return sorted(p.stem for p in TESTDATA_DIR.glob("*.json"))
