from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import asdict
from time import time

from app.models.rate_limit import CounterSlot, UserCounterRecord


class DistributedRateLimitRepository:
    def __init__(self, node_id: str, window_seconds: int) -> None:
        self.node_id = node_id
        self.window_seconds = window_seconds
        self._lock = asyncio.Lock()
        self._records: dict[str, UserCounterRecord] = {}

    async def record_hit(self, user_key: str, now: float | None = None) -> int:
        current_time = time() if now is None else now
        async with self._lock:
            self._prune_expired_locked(current_time)
            record = self._records.setdefault(user_key, UserCounterRecord())
            slot = record.slots.setdefault(self.node_id, CounterSlot())
            slot.count += 1
            slot.expires_at = current_time + self.window_seconds
            slot.updated_at = current_time
            return self._total_for_record(record)

    async def current_total(self, user_key: str, now: float | None = None) -> int:
        current_time = time() if now is None else now
        async with self._lock:
            self._prune_expired_locked(current_time)
            record = self._records.get(user_key)
            if record is None:
                return 0
            return self._total_for_record(record)

    async def snapshot(self, now: float | None = None) -> dict[str, dict[str, dict[str, float | int]]]:
        current_time = time() if now is None else now
        async with self._lock:
            self._prune_expired_locked(current_time)
            return {
                user_key: {slot_key: asdict(slot_value) for slot_key, slot_value in record.slots.items()}
                for user_key, record in self._records.items()
            }

    async def merge_snapshot(
        self,
        snapshot: Mapping[str, Mapping[str, Mapping[str, float | int]]],
        received_at: float | None = None,
        now: float | None = None,
    ) -> None:
        current_time = time() if now is None else now
        envelope_time = current_time if received_at is None else received_at
        async with self._lock:
            self._prune_expired_locked(current_time)
            for user_key, slots in snapshot.items():
                record = self._records.setdefault(user_key, UserCounterRecord())
                for node_id, payload in slots.items():
                    incoming_count = int(payload.get("count", 0))
                    incoming_expires_at = float(payload.get("expires_at", 0.0))
                    incoming_updated_at = float(payload.get("updated_at", envelope_time))
                    if incoming_expires_at <= current_time:
                        continue
                    current_slot = record.slots.get(node_id)
                    if current_slot is None:
                        record.slots[node_id] = CounterSlot(
                            count=incoming_count,
                            expires_at=incoming_expires_at,
                            updated_at=incoming_updated_at,
                        )
                        continue
                    if incoming_updated_at > current_slot.updated_at:
                        current_slot.count = incoming_count
                        current_slot.expires_at = incoming_expires_at
                        current_slot.updated_at = incoming_updated_at
                    elif incoming_updated_at == current_slot.updated_at and incoming_count > current_slot.count:
                        current_slot.count = incoming_count
                        current_slot.expires_at = incoming_expires_at

    async def janitor(self, now: float | None = None) -> None:
        current_time = time() if now is None else now
        async with self._lock:
            self._prune_expired_locked(current_time)

    def _prune_expired_locked(self, current_time: float) -> None:
        expired_users: list[str] = []
        for user_key, record in self._records.items():
            expired_slots = [slot_key for slot_key, slot in record.slots.items() if slot.expires_at <= current_time]
            for slot_key in expired_slots:
                del record.slots[slot_key]
            if not record.slots:
                expired_users.append(user_key)
        for user_key in expired_users:
            del self._records[user_key]

    @staticmethod
    def _total_for_record(record: UserCounterRecord) -> int:
        return sum(slot.count for slot in record.slots.values())
