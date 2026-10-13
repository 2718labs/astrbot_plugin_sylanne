"""AstrBot entry configuration contract; advanced intent stays in the WebUI."""
import json
from pathlib import Path


def test_astrbot_plugin_config_schema_matches_runtime_settings():
    root = Path(__file__).resolve().parents[4]
    schema = json.loads((root / "_conf_schema.json").read_text(encoding="utf-8-sig"))
    assert set(schema) == {"enabled", "authority_profile", "llm_provider_id", "model_selection", "webui", "modules"}
    assert schema["enabled"]["type"] == "bool"
    assert schema["enabled"]["default"] is False
    profile = schema["authority_profile"]
    assert profile["type"] == "string" and profile["default"] == "default"
    assert "名称不是授权" in profile["hint"] and "密钥" in profile["hint"]
    assert "endpoint" not in profile and "authority_id" not in profile
    model = schema["llm_provider_id"]
    assert model["type"] == "string" and model["default"] == ""
    assert model["_special"] == "select_provider"
    assert "不自动采用第一个模型" in model["hint"]
    webui = schema["webui"]["items"]
    assert set(webui) == {"enabled", "bind", "port"}
    assert webui["enabled"]["default"] is True
    assert webui["bind"]["default"] == "0.0.0.0" and webui["port"]["default"] == 2718
    modules = schema["modules"]["items"]
    assert set(modules) == {f"d{number:02d}" for number in range(1, 14)}
    assert all(item["type"] == "bool" and item["default"] is True for item in modules.values())
    assert "已有工作的终态、结算、恢复" in schema["modules"]["hint"]
    selection = schema["model_selection"]
    assert selection["invisible"] is True and selection["items"]["version"]["default"] == 1
    assert all(item["invisible"] is True and item["default"] == ""
        for item in selection["items"]["overrides"]["items"].values())
