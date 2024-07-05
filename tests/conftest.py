import os

import pytest


@pytest.fixture()
def set_testing():
    os.environ["TESTING"] = "true"
    yield
    del os.environ["TESTING"]
