from dataclasses import dataclass
from typing import Optional

@dataclass
class Model:
    name: str
    api_key: str
    base_url: Optional[str] = None   # None → use OpenRouter default



