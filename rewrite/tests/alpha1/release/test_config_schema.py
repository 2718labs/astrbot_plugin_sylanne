import json
from pathlib import Path


def test_astrbot_plugin_config_schema_matches_runtime_settings():
    root = Path(__file__).resolve().parents[4]
    schema = json.loads((root / "_conf_schema.json").read_text(encoding="utf-8-sig"))

    assert set(schema) == {"enabled", "authority_profile"}
    assert schema["enabled"]["type"] == "bool"
    assert schema["enabled"]["default"] is False
    profile = schema["authority_profile"]
    assert profile["type"] == "string"
    assert profile["default"] == "default"
    assert "1–64" in profile["hint"]
    assert "CA" in profile["hint"] and "客户端密钥" in profile["hint"]
    assert "endpoint" not in profile and "authority_id" not in profile
