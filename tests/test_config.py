import os
from pathlib import Path
from unittest.mock import mock_open, patch

import pytest
from cryptography.fernet import Fernet

from zsuite.config import load_config, load_env
from zsuite.exceptions import MissingVaultKey


def test_load_config():
    # Generate a key for encryption
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(b"test_password")

    # Mock configuration data
    config_data = f"""
    database:
        host: localhost
        password: !secret {encrypted_password.decode()}
    """
    # Mock environment variables and file opening
    with (
        patch.dict(os.environ, {"CONFIG_FILE": "/fake/path", "VAULT_KEY": key.decode()}),
        patch("builtins.open", mock_open(read_data=config_data)),
    ):
        config = load_config()
        assert config == {"database": {"host": "localhost", "password": "test_password"}}


def test_load_config_no_config_file_env_var():
    with patch.dict(os.environ, {}, clear=True), pytest.raises(Exception, match="CONFIG_FILE not set"):
        load_config()


def test_load_config_encrypted_value_no_decryption_key():
    # Mock configuration data with encrypted password
    config_data = """
    database:
        host: localhost
        password: !secret encryptedpassword
    """
    # Mock environment variables and file opening
    with (
        patch.dict(os.environ, {"CONFIG_FILE": "/fake/path"}),
        patch("builtins.open", mock_open(read_data=config_data)),
        pytest.raises(
            MissingVaultKey,
            match="Encrypted value found but no decryption key provided.",
        ),
    ):
        load_config()


def test_load_env():
    test_file_path = Path(__file__).parent.absolute()
    env_file_path = test_file_path / "env_test.env"

    load_env(env_file_path, required=True)
    assert os.getenv("TEST_VARIABLE") == "test_value"

    # Test case: File does not exist and required=True
    with pytest.raises(FileNotFoundError):
        load_env(".does_not_exist", required=True)

    # Test case: File does not exist and required=False (should print warning)
    load_env(".does_not_exist", required=False)
