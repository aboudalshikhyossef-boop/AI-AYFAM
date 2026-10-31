"""Regression tests for phase-two security hardening."""

from unittest.mock import patch

from config import settings as settings_module
from utils import http_client


class FakeKeyring:
    def __init__(self):
        self.values = {}

    def get_password(self, service, name):
        return self.values.get((service, name))

    def set_password(self, service, name, value):
        self.values[(service, name)] = value

    def delete_password(self, service, name):
        key = (service, name)
        if key not in self.values:
            raise KeyError(name)
        del self.values[key]


def test_clearing_secret_removes_keyring_value_and_does_not_restore_it(tmp_path):
    fake_keyring = FakeKeyring()
    fake_keyring.set_password(settings_module._KEYRING_SERVICE, "github_token", "old-secret")
    defaults = {**settings_module.DEFAULT_SETTINGS, "report_dir": str(tmp_path / "reports")}

    with (
        patch.object(settings_module, "CONFIG_DIR", tmp_path / ".ayfam"),
        patch.object(settings_module, "CONFIG_FILE", tmp_path / ".ayfam" / "config.json"),
        patch.object(settings_module, "DEFAULT_SETTINGS", defaults),
        patch.object(settings_module, "keyring", fake_keyring),
    ):
        config = settings_module.Settings()
        assert config.get("github_token") == "old-secret"

        config.set("github_token", "")

        assert fake_keyring.get_password(settings_module._KEYRING_SERVICE, "github_token") is None
        reloaded = settings_module.Settings()
        assert reloaded.get("github_token") == ""


def test_urllib_streaming_response_reads_lazily_and_closes():
    from unittest.mock import MagicMock, patch

    response = MagicMock()
    response.read.side_effect = [b"ab", b"cd", b""]
    wrapper = http_client.ResponseWrapper(200, None, raw_response=response)

    response.read.assert_not_called()
    assert list(wrapper.iter_content(chunk_size=2)) == [b"ab", b"cd"]
    assert response.read.call_count == 3
    response.close.assert_called_once()
