import pytest

from zsuite import SVC, SVCObj, config_var


def test_svc_stores_config():
    config = {"some_key": "some_value"}
    service = SVC(config=config)
    assert service.config is config
    assert SVCObj().svc.config is config


def test_svc_defaults():
    service = SVC()
    assert service.config is None
    assert service._unittesting is False


def test_svc_stores_unittesting():
    service = SVC(unittesting=True)
    assert service._unittesting is True


def test_svc_stores_extra_kwargs_as_attributes():
    service = SVC(vault_key="abc123", custom_thing=42)
    assert service.vault_key == "abc123"
    assert service.custom_thing == 42


def test_svc_registers_globally():
    service = SVC()
    assert SVCObj.svc is service
    assert SVCObj().svc is service


def test_config_var_reads_svc_config(monkeypatch):
    monkeypatch.delenv("SVC_TEST_KEY", raising=False)
    SVC(config={"SVC_TEST_KEY": "from-svc"})
    assert config_var("SVC_TEST_KEY") == "from-svc"


def test_config_var_svc_config_case_insensitive(monkeypatch):
    monkeypatch.delenv("SVC_TEST_KEY", raising=False)
    SVC(config={"svc_test_key": "from-svc-lower"})
    assert config_var("SVC_TEST_KEY") == "from-svc-lower"


def test_config_var_env_beats_svc_config(monkeypatch):
    monkeypatch.setenv("SVC_TEST_KEY", "from-env")
    SVC(config={"SVC_TEST_KEY": "from-svc"})
    assert config_var("SVC_TEST_KEY") == "from-env"


def test_config_var_default_when_missing_everywhere(monkeypatch):
    monkeypatch.delenv("SVC_TEST_KEY", raising=False)
    SVC(config={})
    assert config_var("SVC_TEST_KEY", "fallback") == "fallback"


def test_config_var_raises_when_missing_and_no_default(monkeypatch):
    monkeypatch.delenv("SVC_TEST_KEY", raising=False)
    SVC(config={})
    with pytest.raises(ValueError):
        config_var("SVC_TEST_KEY")
