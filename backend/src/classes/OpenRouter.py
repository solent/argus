"""
OpenRouter API Client

A clean, modular client for interacting with the OpenRouter API,
or any OpenAI-compatible endpoint (Ollama, vLLM, etc.).

Main API:
    - ask(prompt, system_prompt, model, config) -> APIResponse
"""

import time
import requests
from typing import Dict, Optional
from dataclasses import dataclass


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class ModelConfig:
    """Configuration for an LLM model"""
    name: str
    max_tokens: int = 10000
    temperature: float = 0.0
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0


@dataclass
class APIResponse:
    """Response from the API"""
    content: str
    model: str
    tokens_used: Optional[int] = None
    finish_reason: Optional[str] = None
    raw_response: Optional[Dict] = None


# ============================================================================
# OpenRouter / OpenAI-compatible API Client
# ============================================================================

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


class OpenRouter:
    def __init__(
        self,
        api_key: Optional[str],
        default_model: str = "anthropic/claude-3-sonnet",
        base_url: str = OPENROUTER_BASE_URL,
        min_interval: float = 0.5,
        timeout: int = 120,
    ):
        """
        Parameters
        ----------
        api_key       : Bearer token. Pass None or empty string for local endpoints (Ollama).
        default_model : Model ID used when ask() is called without an explicit model.
        base_url      : Base URL of the API. Defaults to OpenRouter.
                        For Ollama: "http://localhost:11434/v1"
                        For vLLM:  "http://localhost:8001/v1"
        min_interval  : Minimum seconds between requests (rate limiting).
        timeout       : HTTP read timeout in seconds. Use a large value for local models
                        (large models on shared servers can take several minutes to respond).
        """
        self.api_key = api_key or ""
        self.default_model = default_model
        self.base_url = base_url.rstrip("/")
        self.min_interval = min_interval
        self.timeout = timeout
        self.last_request_time = 0.0

        self.headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/security-analysis-toolkit",
            "X-Title": "Security Analysis Toolkit",
        }
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"

    def _rate_limit(self) -> None:
        now = time.time()
        delta = now - self.last_request_time
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self.last_request_time = time.time()

    def ask(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        config: Optional[ModelConfig] = None,
        retries: int = 3,
    ) -> APIResponse:
        """Query the LLM. This is the only public method you should need."""

        model = model or self.default_model
        config = config or ModelConfig(name=model)

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": config.max_tokens,
            "temperature": config.temperature,
            "top_p": config.top_p,
            "frequency_penalty": config.frequency_penalty,
            "presence_penalty": config.presence_penalty,
        }

        endpoint = f"{self.base_url}/chat/completions"
        last_error = None

        for attempt in range(retries):
            try:
                self._rate_limit()

                response = requests.post(
                    endpoint,
                    headers=self.headers,
                    json=payload,
                    timeout=self.timeout,
                )
                response.raise_for_status()

                data = response.json()
                choice = data["choices"][0]

                return APIResponse(
                    content=choice["message"]["content"],
                    model=model,
                    tokens_used=data.get("usage", {}).get("total_tokens"),
                    finish_reason=choice.get("finish_reason"),
                    raw_response=data,
                )

            except Exception as e:
                last_error = e
                if attempt < retries - 1:
                    wait = 2 ** attempt
                    print(f"[RETRY {attempt + 1}/{retries - 1}] {model} — {e} — retrying in {wait}s")
                    time.sleep(wait)

        raise RuntimeError(f"API request to {endpoint} failed: {last_error}")
