from cryptography.fernet import Fernet

from zsuite.helpers import want_bytes


def decrypt_fernet_str(key: str | bytes, value: str | bytes) -> str:
    f = Fernet(want_bytes(key))
    return f.decrypt(want_bytes(value)).decode()


def encrypt_fernet_str(key: str | bytes, value: str | bytes) -> str:
    f = Fernet(want_bytes(key))
    return f.encrypt(want_bytes(value)).decode()
