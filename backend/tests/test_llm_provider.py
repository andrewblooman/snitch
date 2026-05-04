"""Tests for LLM provider selection and Ollama response parsing."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.llm_provider import (
    AnthropicProvider,
    MockProvider,
    OllamaProvider,
    get_llm_provider,
)


def test_mock_provider_when_no_config(monkeypatch):
    monkeypatch.setattr("app.services.llm_provider.settings.ANTHROPIC_API_KEY", None)
    monkeypatch.setattr("app.services.llm_provider.settings.OLLAMA_URL", None)
    assert isinstance(get_llm_provider(), MockProvider)


def test_ollama_provider_when_url_set(monkeypatch):
    monkeypatch.setattr("app.services.llm_provider.settings.ANTHROPIC_API_KEY", None)
    monkeypatch.setattr("app.services.llm_provider.settings.OLLAMA_URL", "http://localhost:11434")
    monkeypatch.setattr("app.services.llm_provider.settings.OLLAMA_MODEL", "llama3.1")
    provider = get_llm_provider()
    assert isinstance(provider, OllamaProvider)


def test_anthropic_provider_when_key_set(monkeypatch):
    monkeypatch.setattr("app.services.llm_provider.settings.ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setattr("app.services.llm_provider.settings.ANTHROPIC_MODEL", "claude-sonnet-4-6")
    monkeypatch.setattr("app.services.llm_provider.settings.OLLAMA_URL", None)
    provider = get_llm_provider()
    assert isinstance(provider, AnthropicProvider)


def test_anthropic_takes_priority_over_ollama(monkeypatch):
    monkeypatch.setattr("app.services.llm_provider.settings.ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setattr("app.services.llm_provider.settings.ANTHROPIC_MODEL", "claude-sonnet-4-6")
    monkeypatch.setattr("app.services.llm_provider.settings.OLLAMA_URL", "http://localhost:11434")
    monkeypatch.setattr("app.services.llm_provider.settings.OLLAMA_MODEL", "llama3.1")
    provider = get_llm_provider()
    assert isinstance(provider, AnthropicProvider)


async def test_ollama_provider_parses_response():
    provider = OllamaProvider(url="http://localhost:11434", model="llama3.1")

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"message": {"content": "Here is your remediation plan."}}

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("app.services.llm_provider.httpx.AsyncClient", return_value=mock_client):
        result = await provider.complete("fix my code", max_tokens=512)

    assert result.text == "Here is your remediation plan."
    assert result.model == "llama3.1"


async def test_ollama_provider_raises_on_http_error():
    import httpx

    provider = OllamaProvider(url="http://localhost:11434", model="llama3.1")

    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "500", request=MagicMock(), response=MagicMock()
    )

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("app.services.llm_provider.httpx.AsyncClient", return_value=mock_client):
        with pytest.raises(httpx.HTTPStatusError):
            await provider.complete("fix my code")
