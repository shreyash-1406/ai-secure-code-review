"""
LLM client.

Talks to any OpenAI-compatible chat endpoint. By default that is a local
Ollama server, so source code never leaves the machine, which matters when
reviewing private or client code.

Configuration (environment variables):
    LLM_BASE_URL   default http://localhost:11434/v1   (Ollama)
    LLM_MODEL      default qwen2.5-coder:7b
    LLM_API_KEY    only needed for hosted providers
    LLM_TIMEOUT    seconds, default 120

If the endpoint is unreachable the platform keeps working in "rules only"
mode: findings still come from the static scanner, just without AI text.
"""

import json
import os
import re

import requests


class LLMUnavailable(Exception):
    pass


class LLMClient:
    def __init__(self, base_url=None, model=None, api_key=None, timeout=None):
        self.base_url = (base_url or os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")).rstrip("/")
        self.model = model or os.getenv("LLM_MODEL", "qwen2.5-coder:7b")
        self.api_key = api_key or os.getenv("LLM_API_KEY", "ollama")
        self.timeout = int(timeout or os.getenv("LLM_TIMEOUT", "120"))

    def available(self) -> bool:
        try:
            r = requests.get(f"{self.base_url}/models", timeout=3,
                             headers={"Authorization": f"Bearer {self.api_key}"})
            return r.ok
        except requests.RequestException:
            return False

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        try:
            r = requests.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "temperature": temperature,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
                timeout=self.timeout,
            )
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except (requests.RequestException, KeyError, ValueError) as exc:
            raise LLMUnavailable(str(exc)) from exc


def extract_json(text: str):
    """Models sometimes wrap JSON in ```json fences or add chatter; pull out the object."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", text, re.S)
    candidate = fenced.group(1) if fenced else text
    start = min([i for i in (candidate.find("{"), candidate.find("[")) if i != -1], default=-1)
    if start == -1:
        raise ValueError("no JSON found in model output")
    end = max(candidate.rfind("}"), candidate.rfind("]"))
    return json.loads(candidate[start:end + 1])
