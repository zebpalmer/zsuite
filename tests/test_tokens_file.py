import pytest
import yaml

from zsuite.webservice.auth import load_persistent_tokens


def test_load_persistent_tokens_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_persistent_tokens("nonexistentfile.yaml")


def test_load_persistent_tokens_reads_file(tmp_path):
    # Mock the file content to match the new YAML structure
    mock_file_content = """---
users:
  - username: "alice"
    roles:
      - "admin"
      - "developer"
    tokens:
      - "abc1234567890123"
      - "xyz9876543210987"
"""

    tokens_file = tmp_path / "tokens.yaml"
    tokens_file.write_text(mock_file_content)

    result = load_persistent_tokens(str(tokens_file))

    expected_result = yaml.safe_load(mock_file_content)
    assert result == expected_result["users"]


def test_load_multiple_users(tmp_path):
    # Mock the file content to match the new YAML structure
    mock_file_content = """---
users:
  - username: "alice"
    roles:
      - "admin"
      - "developer"
    tokens:
      - "abc1234567890123"
      - "xyz9876543210987"
  - username: "bob"
    roles:
      - "sysadmin"
    tokens:
      - "mno7654321098765"
"""

    tokens_file = tmp_path / "tokens.yaml"
    tokens_file.write_text(mock_file_content)

    result = load_persistent_tokens(str(tokens_file))
    expected_result = yaml.safe_load(mock_file_content)

    assert result == expected_result["users"]
    assert len(result) == 2
    assert result[0]["username"] == "alice"
    assert result[1]["username"] == "bob"


def test_load_persistent_tokens_not_a_directory(tmp_path):
    """A path routed through an existing FILE surfaces as FileNotFoundError.

    yaml_utils converts the underlying NotADirectoryError before auth sees it.
    """
    blocker = tmp_path / "blocker.txt"
    blocker.write_text("i am a file, not a directory")

    with pytest.raises(FileNotFoundError):
        load_persistent_tokens(str(blocker / "tokens.yaml"))


def test_load_persistent_tokens_corrupt_yaml(tmp_path):
    from zsuite.exceptions import ZSuiteException

    bad = tmp_path / "tokens.yaml"
    bad.write_text("users: [unclosed\n : :")

    with pytest.raises(ZSuiteException):
        load_persistent_tokens(str(bad))


def test_load_persistent_tokens_no_file_specified(monkeypatch, caplog):
    monkeypatch.delenv("AUTH_TOKENS_FILE", raising=False)
    assert load_persistent_tokens(None) is None
