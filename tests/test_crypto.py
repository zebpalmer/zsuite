from cryptography.fernet import Fernet

from zsuite.crypto import decrypt_fernet_str, encrypt_fernet_str
from zsuite.helpers import want_bytes


def test_round_trip_str():
    key = Fernet.generate_key().decode()
    value = "some_secret_data"
    encrypted_value = encrypt_fernet_str(key, value)
    decrypted_value = decrypt_fernet_str(key, encrypted_value)
    assert decrypted_value == value


def test_round_trip_bytes():
    key = Fernet.generate_key()
    value = b"some_secret_data"
    encrypted_value = encrypt_fernet_str(key, value)
    decrypted_value = decrypt_fernet_str(key, encrypted_value)
    assert decrypted_value == value.decode()


def test_mixed_types():
    key_str = Fernet.generate_key().decode()
    key_bytes = want_bytes(key_str)
    value_str = "some_secret_data"
    value_bytes = want_bytes(value_str)

    encrypted_value_str = encrypt_fernet_str(key_str, value_str)
    decrypted_value_str = decrypt_fernet_str(key_str, encrypted_value_str)
    assert decrypted_value_str == value_str

    encrypted_value_bytes = encrypt_fernet_str(key_bytes, value_bytes)
    decrypted_value_bytes = decrypt_fernet_str(key_bytes, encrypted_value_bytes)
    assert decrypted_value_bytes == value_bytes.decode()
