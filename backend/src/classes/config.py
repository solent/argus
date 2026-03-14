import os
from pathlib import Path
from .Model import Model
from typing import Dict
from collections import OrderedDict
import requests

# ──────────────────────────────────────────────────────────────
# Cloud API (OpenRouter) — lib resolution, CVE context, judges
# ──────────────────────────────────────────────────────────────
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_BASE    = "https://openrouter.ai/api/v1"

# ──────────────────────────────────────────────────────────────
# On-premise model — code analysis (never sends user code to cloud)
#
# Cloud stand-in default: mistralai/devstral via OpenRouter.
#   devstral is Mistral's coding-focused model — much better at step-by-step
#   taint analysis and structured JSON output than a generic 7B instruct model.
#
# Recommended local Ollama models (best → good):
#   devstral:24b          — purpose-built for code analysis  ⭐ recommended
#   qwen3-coder-next:latest — strong coder, newer Qwen3 line
#   qwen3:32b             — solid general + code reasoning
#   deepseek-r1:70b       — best reasoning, needs ~40 GB VRAM
#
# Minimum viable: 24B parameters.  7B models miss taint paths and CVE details.
#
# To switch to a real on-premise Ollama instance:
#   ON_PREMISE_BASE_URL=http://localhost:11434/v1
#   ON_PREMISE_MODEL=devstral:24b
#   ON_PREMISE_API_KEY=    (leave empty — Ollama needs no auth key)
# ──────────────────────────────────────────────────────────────
ON_PREMISE_BASE_URL = os.getenv("ON_PREMISE_BASE_URL") or "http://ollama.llm.solent.fr/v1"
ON_PREMISE_MODEL    = os.getenv("ON_PREMISE_MODEL") or "devstral:24b"
# Use `or` so that an empty-string env var (ON_PREMISE_API_KEY=) still falls back
# to the cloud key when the on-premise endpoint is OpenRouter.
ON_PREMISE_API_KEY  = os.getenv("ON_PREMISE_API_KEY") or OPENROUTER_API_KEY or ""

# Legacy alias kept for backward compat
MODEL_NAME = ON_PREMISE_MODEL

BASE_DIR      = Path(__file__).resolve().parent
EXPLOITDB_DIR = BASE_DIR / "exploitdb"
CSV_PATH      = EXPLOITDB_DIR / "files_exploits.csv"
NVD_API_URL   = "https://services.nvd.nist.gov/rest/json/cves/1.0"
NVD_API_KEY   = os.getenv("NVD_API_KEY")

# ──────────────────────────────────────────────────────────────
# Judge models — strong cloud models used for benchmarking
# ──────────────────────────────────────────────────────────────
JUDGE_MODELS = [
    "google/gemini-2.5-flash",    # best Flash reasoning,    ~$0.15/M
    "deepseek/deepseek-chat",     # DeepSeek V3, quality/price, ~$0.14/M
    "anthropic/claude-3-haiku",   # solid Anthropic,           ~$0.25/M
]

PRIORITY_MODELS = [ON_PREMISE_MODEL] + JUDGE_MODELS


def get_openrouter_models(api_key: str, limit: int = 10) -> Dict[str, Model]:
    """
    Returns {model_id: Model}.  Priority models are always included if available.
    Fills remaining slots with one model per provider up to `limit`.
    """
    headers = {"Authorization": f"Bearer {api_key}"}
    resp = requests.get(f"{OPENROUTER_BASE}/models", headers=headers)
    resp.raise_for_status()
    all_models_data = resp.json().get("data", [])

    available_ids = {m.get("id") for m in all_models_data if m.get("id")}

    selected = OrderedDict()

    for mid in PRIORITY_MODELS:
        if mid in available_ids:
            selected[mid] = Model(name=mid, api_key=api_key)

    seen_providers = {mid.split("/")[0] for mid in selected}
    for m in all_models_data:
        if len(selected) >= limit:
            break
        model_id = m.get("id")
        if not model_id or model_id in selected:
            continue
        provider = model_id.split("/")[0]
        if provider in seen_providers:
            continue
        seen_providers.add(provider)
        selected[model_id] = Model(name=model_id, api_key=api_key)

    return selected


class Config:
    # On-premise model: used for code analysis (extracted_code never leaves this endpoint)
    model_local: Model = Model(
        name=ON_PREMISE_MODEL,
        api_key=ON_PREMISE_API_KEY,
        base_url=ON_PREMISE_BASE_URL,
    )

    # Backward-compat alias
    model_on_premise: Model = model_local

    # Cloud model: used for library resolution, CVE context enrichment (no user code)
    model_cloud: Model = Model(
        name=JUDGE_MODELS[0],           # strong cloud model for context
        api_key=OPENROUTER_API_KEY or "",
        base_url=OPENROUTER_BASE,
    )

    # Full model catalogue populated at startup by server.py
    models: Dict[str, Model] = {}
