"""Pengaturan harness dari environment variable atau file harness/.env.

AI yang dipakai adalah model lokal dengan API kompatibel OpenAI (Ollama, LM Studio, llama.cpp
server, vLLM, ...). Selama LLM_BASE_URL / LLM_MODEL kosong, harness tetap jalan untuk review
manual, tetapi tombol proses AI menolak dengan pesan "AI belum dikonfigurasi".
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

HARNESS_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = HARNESS_DIR / ".env"


def _load_env_file(path: Path) -> None:
    """Pembaca .env sederhana (KEY=VALUE per baris, # komentar). Env yang sudah ada tidak ditimpa."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass(frozen=True)
class Settings:
    llm_base_url: str   # mis. http://127.0.0.1:11434/v1 (Ollama)
    llm_model: str      # mis. qwen2.5:7b-instruct
    llm_api_key: str    # biasanya kosong untuk model lokal
    llm_timeout: int    # detik per panggilan
    max_percobaan: int  # berapa kali AI diminta mengulang jika hasilnya tidak lolos pemeriksaan
    data_dir: Path      # tempat menyimpan pekerjaan (job) dan cache hasil AI

    @property
    def ai_siap(self) -> bool:
        return bool(self.llm_base_url and self.llm_model)


def load_settings() -> Settings:
    _load_env_file(ENV_FILE)
    data_dir = Path(os.environ.get("HARNESS_DATA_DIR", "") or HARNESS_DIR / "data")
    return Settings(
        llm_base_url=os.environ.get("LLM_BASE_URL", "").strip().rstrip("/"),
        llm_model=os.environ.get("LLM_MODEL", "").strip(),
        llm_api_key=os.environ.get("LLM_API_KEY", "").strip(),
        llm_timeout=int(os.environ.get("LLM_TIMEOUT", "180")),
        max_percobaan=max(1, int(os.environ.get("LLM_MAX_PERCOBAAN", "3"))),
        data_dir=data_dir,
    )
