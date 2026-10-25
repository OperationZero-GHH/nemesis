"""Tests for configuration loading and secret redaction."""

from __future__ import annotations

from nemesis_toolkit.core.config import get_settings


def test_environment_and_yaml_sources(tmp_path, monkeypatch):
    config = tmp_path / "toolconfig.yaml"
    config.write_text("crawl_depth: 4\nserpapi_key: yaml-key\n", encoding="utf-8")
    monkeypatch.setenv("NEMESIS_CONFIG_FILE", str(config))
    monkeypatch.setenv("NEMESIS_SERPAPI_KEY", "env-key")
    monkeypatch.setenv("NEMESIS_CRAWL_DEPTH", "3")
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.crawl_depth == 3  # environment beats YAML
    assert settings.api_key("serpapi_key") == "env-key"


def test_yaml_source_is_used_when_env_absent(tmp_path, monkeypatch):
    config = tmp_path / "toolconfig.yaml"
    config.write_text("crawl_depth: 4\nserpapi_key: yaml-key\n", encoding="utf-8")
    monkeypatch.setenv("NEMESIS_CONFIG_FILE", str(config))
    monkeypatch.delenv("NEMESIS_CRAWL_DEPTH", raising=False)
    monkeypatch.delenv("NEMESIS_SERPAPI_KEY", raising=False)
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.crawl_depth == 4
    assert settings.api_key("serpapi_key") == "yaml-key"


def test_public_dict_redacts_keys():
    settings = get_settings()
    payload = settings.public_dict()
    assert "serpapi_key" in payload
    assert payload["serpapi_key"] in (None, "***configured***")


def test_blank_api_key_is_missing(monkeypatch):
    monkeypatch.setenv("NEMESIS_SERPAPI_KEY", "   ")
    get_settings.cache_clear()
    assert get_settings().api_key("serpapi_key") is None
