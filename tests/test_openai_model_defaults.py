from config.model_defaults import OPENAI_DEFAULT_MODEL as SHARED_OPENAI_DEFAULT_MODEL
from config.settings import DEFAULT_SETTINGS
from engine.ai_assistant import OPENAI_DEFAULT_MODEL


def test_openai_runtime_default_has_one_source():
    assert OPENAI_DEFAULT_MODEL == SHARED_OPENAI_DEFAULT_MODEL
    assert DEFAULT_SETTINGS["openai_model"] == SHARED_OPENAI_DEFAULT_MODEL
