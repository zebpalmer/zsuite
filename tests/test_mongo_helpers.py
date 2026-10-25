from unittest.mock import patch

import pytest
from flask import abort  # noqa

from zsuite.exceptions import MongoQueryError
from zsuite.webservice import sanitize_mongo_query, validate_mongo_query


def test_with_valid_data():
    """Test with valid data without any '$' in keys or values."""
    data = {
        "username": "john",
        "profile": {"age": 30, "interests": ["coding", "music"]},
        "tags": ["developer", "python"],
    }
    try:
        sanitize_mongo_query(data)
    except Exception as e:
        pytest.fail(f"Unexpected exception raised: {e}")


def test_invalid_key():
    """Test data with invalid '$' in keys."""
    data = {"$invalid": "test", "name": "john"}
    with pytest.raises(Exception) as exc_info:
        sanitize_mongo_query(data)
    assert "400" in str(exc_info.value)
    assert "Invalid query parameter key: $invalid" in str(exc_info.value)


def test_valid_mongo_operator_lt():
    """Test data with valid MongoDB '$lt' operator."""
    data = {"age": {"$lt": 30}}
    try:
        sanitize_mongo_query(data)
    except Exception as e:
        pytest.fail(f"Unexpected exception raised with '$lt' operator: {e}")


def test_dollar_prefixed_value_rejected():
    """'$'-prefixed string values are field-reference injection risk in aggregation contexts."""
    data = {"username": "$admin", "profile": {"age": 30}}
    with pytest.raises(Exception) as exc_info:
        sanitize_mongo_query(data)
    assert "400" in str(exc_info.value)


def test_interior_dollar_in_value_allowed():
    """A '$' elsewhere in a value (prices, free text) is inert in find() and must pass."""
    sanitize_mongo_query({"username": "john$", "note": "costs $5", "profile": {"bio": "a $ b"}})


def test_nested_invalid_key():
    """Test data with nested invalid '$' in keys."""
    data = {"profile": {"$badkey": "value"}, "name": "john"}
    with pytest.raises(Exception) as exc_info:
        sanitize_mongo_query(data)
    assert "400" in str(exc_info.value)
    assert "Invalid query parameter key: $badkey" in str(exc_info.value)


def test_list_with_invalid_data():
    """Test data with a list containing an invalid dictionary."""
    data = {"tags": ["good", {"$badtag": "oops"}]}
    with pytest.raises(Exception) as exc_info:
        sanitize_mongo_query(data)
    assert "400" in str(exc_info.value)
    assert "Invalid query parameter key: $badtag" in str(exc_info.value)


@patch("flask.abort")
def test_no_abort_on_valid_data(mock_abort):
    """Ensure no abort is called on valid data."""
    data = {"username": "alice", "age": 25}
    sanitize_mongo_query(data)
    mock_abort.assert_not_called()


# --- validate_mongo_query (pure core, no Flask) --------------------------------


def test_validate_raises_library_exception_on_bad_key():
    with pytest.raises(MongoQueryError, match=r"Invalid query parameter key: \$where"):
        validate_mongo_query({"$where": "this.age > 18"})


def test_validate_raises_library_exception_on_dollar_prefixed_value():
    with pytest.raises(MongoQueryError, match="prefixed"):
        validate_mongo_query({"name": "$password"})


def test_validate_passes_valid_query():
    validate_mongo_query({"age": {"$gt": 18}, "tags": {"$in": ["a", "b"]}, "note": "costs $5"})


def test_validate_usable_without_flask_context():
    """The pure core raises a catchable library exception, never an HTTP response."""
    with pytest.raises(MongoQueryError):
        validate_mongo_query({"$bad": 1})
