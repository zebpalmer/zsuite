import os
from unittest.mock import MagicMock, patch

import pytest

from zsuite.exceptions import ConfigurationError
from zsuite.mongodb import get_mongo, get_mongo_client, get_mongo_db


class TestGetMongoClient:
    """Tests for get_mongo_client function"""

    @patch("zsuite.mongodb.MongoClient")
    def test_host_only(self, mock_client):
        """Only MONGO_HOST is required; auth is optional; tz_aware defaults True."""
        with patch.dict(os.environ, {"MONGO_HOST": "mongodb://localhost:27017"}, clear=False):
            for var in ["MONGO_USERNAME", "MONGO_PASSWORD", "MONGO_TZ_AWARE"]:
                os.environ.pop(var, None)
            result = get_mongo_client()

            mock_client.assert_called_once_with(
                host="mongodb://localhost:27017",
                tz_aware=True,
            )
            assert result == mock_client.return_value

    @patch("zsuite.mongodb.MongoClient")
    def test_with_auth_config(self, mock_client):
        with patch.dict(
            os.environ,
            {
                "MONGO_HOST": "mongodb://localhost:27017",
                "MONGO_USERNAME": "testuser",
                "MONGO_PASSWORD": "testpass",
            },
        ):
            get_mongo_client()

            call_kwargs = mock_client.call_args[1]
            assert call_kwargs["host"] == "mongodb://localhost:27017"
            assert call_kwargs["username"] == "testuser"
            assert call_kwargs["password"] == "testpass"

    @patch("zsuite.mongodb.MongoClient")
    def test_with_optional_config(self, mock_client):
        """All optional config vars are forwarded to MongoClient."""
        with patch.dict(
            os.environ,
            {
                "MONGO_HOST": "mongodb://localhost:27017",
                "MONGO_REPLICASET": "rs0",
                "MONGO_AUTHSOURCE": "admin",
                "MONGO_READPREFERENCE": "secondaryPreferred",
                "MONGO_TLS": "true",
                "MONGO_TLS_INSECURE": "true",
            },
        ):
            get_mongo_client()

            call_kwargs = mock_client.call_args[1]
            assert call_kwargs["replicaSet"] == "rs0"
            assert call_kwargs["authSource"] == "admin"
            assert call_kwargs["readPreference"] == "secondaryPreferred"
            assert call_kwargs["tls"] is True
            assert call_kwargs["tlsInsecure"] is True
            assert call_kwargs["tz_aware"] is True

    @patch("zsuite.mongodb.MongoClient")
    def test_tz_aware_can_be_disabled(self, mock_client):
        with patch.dict(
            os.environ,
            {"MONGO_HOST": "mongodb://localhost:27017", "MONGO_TZ_AWARE": "false"},
        ):
            get_mongo_client()
            assert mock_client.call_args[1]["tz_aware"] is False

    def test_missing_host_raises(self):
        with patch.dict(os.environ, {}, clear=True), pytest.raises(ConfigurationError, match="MONGO_HOST"):
            get_mongo_client()

    def test_non_boolean_bool_var_raises(self):
        """Strict boolean config: MONGO_TLS_INSECURE=1 must fail, not silently enable."""
        with (
            patch.dict(
                os.environ,
                {"MONGO_HOST": "mongodb://localhost:27017", "MONGO_TLS_INSECURE": "1"},
            ),
            pytest.raises(ConfigurationError, match="MONGO_TLS_INSECURE"),
        ):
            get_mongo_client()


class TestGetMongoDb:
    """Tests for get_mongo_db function"""

    @patch("zsuite.mongodb.get_mongo_client")
    def test_get_mongo_db_creates_client_if_none(self, mock_get_client):
        """Test get_mongo_db creates client when not provided"""
        mock_client = MagicMock()
        mock_db = MagicMock()
        mock_client.test_db = mock_db
        mock_get_client.return_value = mock_client

        with patch.dict(os.environ, {"MONGO_DB_NAME": "test_db"}):
            result = get_mongo_db()

            mock_get_client.assert_called_once()
            assert result == mock_db

    def test_get_mongo_db_uses_provided_client(self):
        """A caller-supplied client is the escape hatch for exotic pymongo options."""
        mock_client = MagicMock()
        mock_db = MagicMock()
        mock_client.test_db = mock_db

        with patch.dict(os.environ, {"MONGO_DB_NAME": "test_db"}):
            result = get_mongo_db(client=mock_client)

            assert result == mock_db

    def test_get_mongo_db_missing_db_name(self):
        mock_client = MagicMock()

        with (
            patch.dict(os.environ, {}, clear=True),
            pytest.raises(ConfigurationError, match="MONGO_DB_NAME"),
        ):
            get_mongo_db(client=mock_client)

    def test_get_mongo_db_with_init_callback(self):
        mock_client = MagicMock()
        mock_db = MagicMock()
        mock_client.test_db = mock_db
        mock_init = MagicMock()

        with patch.dict(os.environ, {"MONGO_DB_NAME": "test_db"}):
            result = get_mongo_db(client=mock_client, init_db=mock_init)

            mock_init.assert_called_once_with(mock_db)
            assert result == mock_db


class TestGetMongo:
    """Tests for the get_mongo convenience function"""

    @patch("zsuite.mongodb.get_mongo_client")
    @patch("zsuite.mongodb.get_mongo_db")
    def test_get_mongo_returns_client_and_db(self, mock_get_db, mock_get_client):
        mock_client = MagicMock()
        mock_db = MagicMock()
        mock_get_client.return_value = mock_client
        mock_get_db.return_value = mock_db

        client, db = get_mongo()

        mock_get_client.assert_called_once()
        mock_get_db.assert_called_once_with(init_db=None, client=mock_client)
        assert client == mock_client
        assert db == mock_db

    @patch("zsuite.mongodb.get_mongo_client")
    @patch("zsuite.mongodb.get_mongo_db")
    def test_get_mongo_with_init_callback(self, mock_get_db, mock_get_client):
        mock_client = MagicMock()
        mock_db = MagicMock()
        mock_init = MagicMock()
        mock_get_client.return_value = mock_client
        mock_get_db.return_value = mock_db

        client, db = get_mongo(init_db=mock_init)

        mock_get_client.assert_called_once()
        mock_get_db.assert_called_once_with(init_db=mock_init, client=mock_client)
        assert client == mock_client
        assert db == mock_db
