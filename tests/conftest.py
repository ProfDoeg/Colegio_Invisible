"""Shared test setup — path wiring and corpus fixtures.

The repo's import convention: consumers put both the repo root and
canonical/ on sys.path (canonical modules import each other flat,
e.g. `from tone import ...`). Tests follow the same convention.
"""
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANON = os.path.join(REPO, "canonical")
for p in (REPO, CANON):
    if p not in sys.path:
        sys.path.insert(0, p)

DATA = os.path.join(REPO, "data")


@pytest.fixture(scope="session")
def repo():
    return REPO


@pytest.fixture(scope="session")
def corpus():
    """The on-chain corpus dataset: one row per quipu, with body bytes on
    disk. Skips the dependent tests entirely if the dataset is absent
    (fresh clone without data/)."""
    import pandas as pd
    csv = os.path.join(DATA, "quipu_data.csv")
    if not os.path.exists(csv):
        pytest.skip("data/quipu_data.csv not present")
    df = pd.read_csv(csv)
    df["body_path"] = df["body_file"].map(
        lambda b: os.path.join(DATA, str(b)) if pd.notna(b) else None)
    return df
