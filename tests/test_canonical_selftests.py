"""Harness every canonical module's embedded self-tests under pytest.

Each canonical/*.py module carries `_selftest_*` functions with embedded
on-chain test vectors (Mi Perrito, the Domrémy bordado, the Maier cert...).
They were previously runnable only as `python canonical/<mod>.py`. This
collects every one of them as an individual pytest case, so a regression
in any module fails by name.
"""
import glob
import importlib
import os

import pytest

CANON = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "canonical")


def _collect():
    cases = []
    for path in sorted(glob.glob(os.path.join(CANON, "*.py"))):
        modname = os.path.splitext(os.path.basename(path))[0]
        if modname.startswith("_"):
            continue
        mod = importlib.import_module(modname)
        for attr in sorted(dir(mod)):
            if attr.startswith("_selftest") and callable(getattr(mod, attr)):
                cases.append(pytest.param(mod, attr, id=f"{modname}.{attr}"))
    return cases


@pytest.mark.parametrize("mod,fn", _collect())
def test_selftest(mod, fn, capsys):
    getattr(mod, fn)()          # self-tests assert internally; silence is success
    capsys.readouterr()         # swallow their progress prints
