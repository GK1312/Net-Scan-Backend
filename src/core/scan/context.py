from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.config import PhaseTimeouts


@dataclass(slots=True)
class ProbeContext:
    ip: str
    timeouts: PhaseTimeouts
    shared: dict[str, Any] = field(default_factory=dict)
