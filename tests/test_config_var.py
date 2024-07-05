import os

import pytest
from cryptography.fernet import Fernet

from zsuite.config import config_var
from zsuite.exceptions import EncryptedValueError, MissingVaultKey


# Test case for retrieving a config variable from os.environ
def test_config_var_from_os_environ(monkeypatch):
    monkeypatch.setenv("MY_CONFIG_VAR", "my_value")
    result = config_var("MY_CONFIG_VAR")
    assert result == "my_value"


# Test case for using default value when config variable is not found
def test_config_var_with_default():
    result = config_var("NON_EXISTING_VAR", default="default_value")
    assert result == "default_value"
    assert config_var("SOME_OTHER_VAR1", default=True) is True
    assert config_var("SOME_OTHER_VAR2", default=False) is False
    assert config_var("SOME_OTHER_VAR2", default=None) is None


# Test case for handling unset config variable and no default provided
def test_config_var_unset_and_no_default():
    with pytest.raises(
        ValueError,
        match="Config variable NON_EXISTING_VAR not set and no default provided",
    ):
        config_var("NON_EXISTING_VAR")


def test_config_var_boolean():
    trues = ["true", "True", "TRUE"]
    falses = ["false", "False", "FALSE"]
    for t in trues:
        os.environ["TEST_VAR"] = t
        assert config_var("TEST_VAR") is True
    for f in falses:
        os.environ["TEST_VAR"] = f
        assert config_var("TEST_VAR") is False


def test_config_var_secret(monkeypatch):
    test_pw = "test_password123!"
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(test_pw.encode())
    env_str = f"!secret {encrypted_password.decode()}"
    monkeypatch.setenv("SECRET_CFG_VAR", env_str)

    # Test case: secret_constructor without key
    with pytest.raises(MissingVaultKey):
        result = config_var("SECRET_CFG_VAR")

    # Test case: secret_constructor with invalid key
    monkeypatch.setenv("VAULT_KEY", "invalid_key")
    with pytest.raises(EncryptedValueError):
        result = config_var("SECRET_CFG_VAR")

    # Test case: secret_constructor with key
    monkeypatch.setenv("VAULT_KEY", key.decode())
    result = config_var("SECRET_CFG_VAR")
    assert result == test_pw
