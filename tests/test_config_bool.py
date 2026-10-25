import pytest

# --- config_bool -------------------------------------------------------------


class TestConfigBool:
    def test_accepts_true_false_strings(self, monkeypatch):
        from zsuite import config_bool

        monkeypatch.setenv("BOOL_TEST_VAR", "true")
        assert config_bool("BOOL_TEST_VAR") is True
        monkeypatch.setenv("BOOL_TEST_VAR", "False")
        assert config_bool("BOOL_TEST_VAR") is False

    def test_accepts_real_bool_default(self, monkeypatch):
        from zsuite import config_bool

        monkeypatch.delenv("BOOL_TEST_VAR", raising=False)
        assert config_bool("BOOL_TEST_VAR", True) is True
        assert config_bool("BOOL_TEST_VAR", False) is False

    def test_none_default_is_tristate(self, monkeypatch):
        from zsuite import config_bool

        monkeypatch.delenv("BOOL_TEST_VAR", raising=False)
        assert config_bool("BOOL_TEST_VAR", None) is None

    @pytest.mark.parametrize("bad", ["0", "1", "yes", "no", "on", "off", "enabled", ""])
    def test_rejects_non_boolean_values(self, monkeypatch, bad):
        from zsuite import config_bool
        from zsuite.exceptions import ConfigurationError

        monkeypatch.setenv("BOOL_TEST_VAR", bad)
        with pytest.raises(ConfigurationError):
            config_bool("BOOL_TEST_VAR")

    def test_missing_without_default_raises(self, monkeypatch):
        from zsuite import config_bool
        from zsuite.exceptions import ConfigurationError

        monkeypatch.delenv("BOOL_TEST_VAR", raising=False)
        with pytest.raises(ConfigurationError):
            config_bool("BOOL_TEST_VAR")
