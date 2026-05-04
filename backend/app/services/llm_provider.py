import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

@dataclass
class LLMResponse:
    text: str
    model: str = field(default="")


class LLMProvider(ABC):
    @abstractmethod
    async def complete(self, prompt: str, max_tokens: int = 4096, use_thinking: bool = False) -> LLMResponse:
        ...


class AnthropicProvider(LLMProvider):
    def __init__(self, api_key: str, model: str):
        self._api_key = api_key
        self._model = model

    async def complete(self, prompt: str, max_tokens: int = 4096, use_thinking: bool = False) -> LLMResponse:
        from anthropic import AsyncAnthropic

        client = AsyncAnthropic(api_key=self._api_key)
        kwargs: dict = {
            "model": self._model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if use_thinking:
            kwargs["thinking"] = {"type": "enabled", "budget_tokens": min(10000, max_tokens - 1)}
        response = await client.messages.create(**kwargs)
        text = "".join(block.text for block in response.content if block.type == "text")
        return LLMResponse(text=text, model=self._model)


class OllamaProvider(LLMProvider):
    def __init__(self, url: str, model: str):
        self._url = url.rstrip("/")
        self._model = model

    async def complete(self, prompt: str, max_tokens: int = 4096, use_thinking: bool = False) -> LLMResponse:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self._url}/api/chat",
                json={
                    "model": self._model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {"num_predict": max_tokens},
                },
            )
            response.raise_for_status()
            data = response.json()
        return LLMResponse(text=data["message"]["content"], model=self._model)


class MockProvider(LLMProvider):
    async def complete(self, prompt: str, max_tokens: int = 4096, use_thinking: bool = False) -> LLMResponse:
        return LLMResponse(text="", model="")


def get_llm_provider() -> LLMProvider:
    if settings.ANTHROPIC_API_KEY:
        return AnthropicProvider(settings.ANTHROPIC_API_KEY, settings.ANTHROPIC_MODEL)
    if settings.OLLAMA_URL:
        return OllamaProvider(settings.OLLAMA_URL, settings.OLLAMA_MODEL)
    return MockProvider()
