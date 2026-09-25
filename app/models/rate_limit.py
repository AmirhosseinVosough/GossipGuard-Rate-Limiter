from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class CounterSlot:
    count: int = 0
    window: int = 0
    expires_at: float = 0.0
    updated_at: float = 0.0


@dataclass(slots=True)
class UserCounterRecord:
    slots: dict[str, CounterSlot] = field(default_factory=dict)
