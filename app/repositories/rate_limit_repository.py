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

    async def try_acquire(self, user_key: str, limit: int, now: float | None = None) -> tuple[bool, int]:
        """Count one request against the current window, unless the window is already full.

        Windows are fixed, numbered floor(now / window_seconds), so every count
        resets at the same boundary however steadily a client sends. Refused
        requests are not counted, so a throttled client gets back in as soon as
        the window rolls over.
        """
        current_time = time() if now is None else now
        window = self._window_for(current_time)
        async with self._lock:
            self._prune_expired_locked(current_time)
            record = self._records.setdefault(user_key, UserCounterRecord())
            total = self._total_for_record(record, window)
            if total >= limit:
                return False, total
            slot = record.slots.get(self.node_id)
            if slot is None or slot.window != window:
                slot = CounterSlot(window=window, expires_at=(window + 1) * self.window_seconds)
                record.slots[self.node_id] = slot
            slot.count += 1
            slot.updated_at = current_time
            return True, total + 1

    async def current_total(self, user_key: str, now: float | None = None) -> int:
        current_time = time() if now is None else now
        async with self._lock:
            self._prune_expired_locked(current_time)
            record = self._records.get(user_key)
            if record is None:
                return 0
            return self._total_for_record(record, self._window_for(current_time))

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
                    # Slots from a node on the old sliding expiry carry no window
                    # and cannot be placed, so they are skipped until it upgrades.
                    if "window" not in payload:
                        continue
                    incoming_count = int(payload.get("count", 0))
                    incoming_window = int(payload["window"])
                    incoming_expires_at = float(payload.get("expires_at", 0.0))
                    incoming_updated_at = float(payload.get("updated_at", envelope_time))
                    if incoming_expires_at <= current_time:
                        continue
                    incoming_slot = CounterSlot(
                        count=incoming_count,
                        window=incoming_window,
                        expires_at=incoming_expires_at,
                        updated_at=incoming_updated_at,
                    )
                    current_slot = record.slots.get(node_id)
                    # A later window supersedes the slot outright and an earlier one
                    # is stale. Within the same window a node's count only grows.
                    if current_slot is None or incoming_window > current_slot.window:
                        record.slots[node_id] = incoming_slot
                        continue
                    if incoming_window < current_slot.window:
                        continue
                    if incoming_updated_at > current_slot.updated_at:
                        record.slots[node_id] = incoming_slot
                    elif incoming_updated_at == current_slot.updated_at and incoming_count > current_slot.count:
                        current_slot.count = incoming_count

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

    def _window_for(self, current_time: float) -> int:
        return int(current_time // self.window_seconds)

    @staticmethod
    def _total_for_record(record: UserCounterRecord, window: int) -> int:
        # A peer whose clock runs ahead can gossip a slot for a window that has
        # not started here yet. It counts once this node reaches that window.
        return sum(slot.count for slot in record.slots.values() if slot.window == window)
