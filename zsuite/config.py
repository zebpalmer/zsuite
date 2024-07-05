import logging
import os

from dotenv import load_dotenv

from .crypto import decrypt_fernet_str
from .exceptions import EncryptedValueError, MissingVaultKey
from .yaml import load_and_decrypt_yaml

# Sentinel value to represent an unset default
UNSET_DEFAULT = object()


def config_var(name: str, default: any = UNSET_DEFAULT) -> any:
    """
    Get a config variable from the service object or environment, prefer environment

    """
    value = default

    if name in os.environ:
        value = os.environ[name]
    # else:
    #     config = getattr(SVCObj().svc, "config", None)
    #     if config is not None:
    #         if name in config:
    #             value = config[name]
    #         elif name.lower() in config:
    #             value = config[name.lower()]

    if value is UNSET_DEFAULT:
        raise ValueError(f"Config variable {name} not set and no default provided")

    if isinstance(value, bytes):
        value = _attempt_decode(name, value)

    if isinstance(value, str):
        value = _normalize_config_string(name, value)

    return value


def _normalize_config_string(name, value):
    if value.lower() == "true":
        value = True
    elif value.lower() == "false":
        value = False
    elif value.startswith("!secret"):
        value = extract_secret(name, value)
    return value


def _attempt_decode(name, value):
    try:
        value = value.decode()
    except Exception as e:
        logging.error(f"Error decoding config var {name}: {e}")
        raise e
    return value


def extract_secret(name, value):
    vault_key = os.getenv("VAULT_KEY")
    if vault_key is None:
        raise MissingVaultKey("Encrypted Config encountered with no VAULT_KEY environment variable set")
    else:
        try:
            value = _decrypt_cfg_var(os.getenv("VAULT_KEY"), value)
        except Exception as e:
            logging.error(f"Error decrypting config var {name}: {e}")
            raise EncryptedValueError(f"Error decrypting config var {name}: {e}") from e
    return value


def _decrypt_cfg_var(key, value):
    value = value.removeprefix("!secret ")
    return decrypt_fernet_str(key, value)


def load_config(decryption_key=None, config_file=None) -> dict:
    """
    Loads a YAML configuration file, decrypting values tagged with "!secret" using the provided decryption key.

    The function registers a custom constructor to handle decryption of values tagged with "!secret" in the YAML file.
    If the decryption_key is not provided, the function uses the secret_constructor without the key.
    If the config_file is not provided, the function looks for the file path in the "CONFIG" environment variable.

    :param decryption_key: Optional; a string representing the Fernet decryption key to be used for decryption.
                           If not provided, the constructor will attempt to use the environment variable "VAULT_KEY".
    :param config_file: Optional; a string representing the path to the YAML configuration file to be loaded.
                        If not provided, the function will look for the path in the "CONFIG" environment variable.
    :return: A dictionary representing the contents of the loaded YAML file, with encrypted values decrypted
    :raises Exception: If neither the config_file parameter nor the "CONFIG" environment variable is set.
    """
    if decryption_key is None:
        decryption_key = os.getenv("VAULT_KEY", None)
    if config_file is None:
        config_file = os.getenv("CONFIG_FILE")
    if config_file is None:
        raise Exception("CONFIG_FILE not set")

    return load_and_decrypt_yaml(decryption_key, config_file)


def load_env(env_file=".env", required=False):
    if os.path.exists(env_file):
        load_dotenv(env_file)
    else:
        if required:
            raise FileNotFoundError(f"Environment file {env_file} not found")
        else:
            print(f"Warning: environment file {env_file} not found")
