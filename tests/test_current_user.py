import pytest
from flask import request

from zsuite.webservice import HALOFlask, current_user, current_user_name
from zsuite.webservice.auth import User


@pytest.fixture
def client():
    app = HALOFlask(__name__)

    @app.route("/")
    def index():
        return "Hello, World!"

    with app.test_client() as client:
        yield client


def test_current_user_no_user(client):
    with client.application.test_request_context("/"):
        assert current_user() is None


def test_current_user_with_user(client):
    user = User("john_doe", ["admin"])
    with client.application.test_request_context("/"):
        request.environ["user"] = user
        assert current_user() == user


def test_current_user_name_no_user(client):
    with client.application.test_request_context("/"):
        assert current_user_name() is None


def test_current_user_name_with_user(client):
    user = User("john_doe", ["admin"])
    with client.application.test_request_context("/"):
        request.environ["user"] = user
        assert current_user_name() == "john_doe"
