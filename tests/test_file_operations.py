import os
import tempfile

from zsuite.file_operations import debug_file_path


def test_debug_file_path(monkeypatch):
    monkeypatch.setenv("FILE_DEBUG", "True")
    with tempfile.NamedTemporaryFile() as temp_file:
        temp_file_name = temp_file.name
        result = debug_file_path(temp_file_name, force_print=True)

        assert result["file_path"] == temp_file_name
        assert result["file_exists"] is True
        assert result["file_readable"] is True
        assert result["file_writable"] is True
        assert result["file_executable"] in [True, False]  # windows doesn't have executable bit
        assert result["file_is_directory"] is False
        assert result["parent_dir_exists"] is True
        assert result["parent_dir_writable"] is True
        assert result["parent_dir_readable"] is True
        assert result["is_absolute"] is True  # Temp files usually have absolute paths
        assert result["absolute_path"] == os.path.abspath(temp_file_name)
