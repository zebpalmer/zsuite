import os

import yaml
from cryptography.fernet import Fernet

from zsuite.helpers import want_bytes

from .exceptions import MissingVaultKey


def secret_constructor(decryption_key: str | bytes = None):
    """Creates and returns a custom YAML constructor function for decrypting values tagged with "!secret".

    This function returns a constructor that can be used with a YAML loader to decrypt scalar values tagged with
    "!secret" in a YAML file. If a decryption_key is provided, it will be used to decrypt the values. If not,
    the function will attempt to use the "VAULT_KEY" environment variable as the decryption key.

    :param decryption_key: Optional; the Fernet decryption key to be used for decryption.
                           If not provided, the returned constructor will use the "VAULT_KEY" environment variable.
    :return: A constructor function that takes a loader and a node, decrypts the value if it's tagged with "!secret",
             and returns the decrypted or original value.
    :raises ValueError: If a value tagged with "!secret" is encountered but no decryption key is provided or found.
    """
    decryption_key = want_bytes(decryption_key)

    def _constructor(loader, node):
        value = loader.construct_scalar(node)
        key = decryption_key if decryption_key is not None else os.getenv("VAULT_KEY")
        if key is None:
            raise ValueError("Encountered encrypted value, but no decryption key was provided.")
        f = Fernet(key)
        return f.decrypt(value.encode()).decode()

    return _constructor


def load_and_decrypt_yaml(decryption_key=None, file_path=None):
    """Loads and parses a YAML file, decrypting values tagged with "!secret" using the provided decryption key.

    :param decryption_key: Optional; String representing the Fernet decryption key to be used for decryption.
    :param file_path: String representing the path to the YAML file to be loaded.
    :return: A dictionary representing the contents of the loaded YAML file, with encrypted values decrypted.
    """
    try:
        # First, read the file without applying any constructors to check for encrypted values
        with open(file_path) as f:
            file_content = f.read()
            if "!secret" in file_content:
                if decryption_key is None:
                    if "VAULT_KEY" in os.environ:
                        decryption_key = os.environ["VAULT_KEY"]
                    else:
                        raise MissingVaultKey("Encrypted value found but no decryption key provided.")
                yaml.constructor.SafeConstructor.add_constructor("!secret", secret_constructor(decryption_key))
        with open(file_path) as f:
            return yaml.safe_load(f)

    except FileNotFoundError:
        raise FileNotFoundError(f"File {file_path} not found") from None
    except NotADirectoryError:
        raise FileNotFoundError(f"File {file_path} directory not found") from None
    except MissingVaultKey:
        raise
    except Exception as e:
        raise Exception(f"Error loading YAML file {file_path}: {e}") from e
