import os

import pytest

from zsuite import SVCObj


@pytest.fixture()
def set_testing():
    os.environ["TESTING"] = "true"
    yield
    del os.environ["TESTING"]


@pytest.fixture(autouse=True)
def _reset_svc():
    """Keep a service container set by one test from leaking config into the next."""
    yield
    SVCObj.svc = None
