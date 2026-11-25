"""Klien AI lokal: API chat kompatibel OpenAI (POST {base_url}/chat/completions).

Memakai library bawaan Python (urllib), tanpa dependensi tambahan. Data hanya dikirim ke
alamat LLM_BASE_URL yang diisi pengguna (model lokal).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Callable

from .config import Settings

# Fungsi chat: menerima daftar pesan, mengembalikan teks jawaban AI.
ChatFn = Callable[[list[dict[str, str]]], str]


class LlmError(RuntimeError):
    """AI tidak bisa dihubungi atau jawabannya tidak terbaca."""


def make_chat(settings: Settings) -> ChatFn:
    if not settings.ai_siap:
        raise LlmError("AI belum dikonfigurasi: isi LLM_BASE_URL dan LLM_MODEL di harness/.env.")
    url = f"{settings.llm_base_url}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if settings.llm_api_key:
        headers["Authorization"] = f"Bearer {settings.llm_api_key}"

    def chat(messages: list[dict[str, str]]) -> str:
        body = {
            "model": settings.llm_model,
            "messages": messages,
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=settings.llm_timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise LlmError(f"AI menjawab HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LlmError(f"AI tidak bisa dihubungi di {settings.llm_base_url}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise LlmError("Jawaban server AI bukan JSON.") from exc
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LlmError("Format jawaban server AI tidak dikenali (bukan format chat completions).") from exc

    return chat
