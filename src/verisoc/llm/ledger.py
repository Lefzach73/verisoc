"""Crash-safe, cross-process spend reservations. No keys or prompt text are stored."""

import json
import os
from datetime import UTC, datetime
from decimal import ROUND_CEILING, Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

from filelock import FileLock

from verisoc.core.errors import BudgetExceeded


def money(value: float | str | Decimal) -> Decimal:
    number = Decimal(str(value))
    if not number.is_finite() or number < 0:
        raise ValueError("Invalid monetary amount")
    return number.quantize(Decimal("0.000000001"), rounding=ROUND_CEILING)


class SpendLedger:
    def __init__(self, path: Path, cap_usd: float) -> None:
        self.path = path
        self.cap = money(cap_usd)
        if self.cap <= 0:
            raise ValueError("Positive study cap required")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = FileLock(str(path) + ".lock", timeout=10)
        with self.lock:
            if path.exists():
                state = self._read()
                if money(state["cap_usd"]) != self.cap:
                    raise ValueError("Cannot change an existing study cap")
            else:
                self._write({"schema_version": "1.0", "cap_usd": str(self.cap), "requests": []})

    def _read(self) -> dict[str, Any]:
        state: dict[str, Any] = json.loads(self.path.read_text())
        if state.get("schema_version") != "1.0" or not isinstance(state.get("requests"), list):
            raise ValueError("Invalid spend ledger")
        return state

    def _write(self, state: dict[str, Any]) -> None:
        temporary = self.path.with_name(self.path.name + ".tmp-" + uuid4().hex)
        try:
            with temporary.open("x") as handle:
                json.dump(state, handle, indent=2, sort_keys=True, allow_nan=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def committed(state: dict[str, Any]) -> Decimal:
        return sum(
            (money(row.get("charged_usd", row["reserved_usd"])) for row in state["requests"]),
            Decimal(0),
        )

    def reserve(self, amount: float, metadata: dict[str, Any]) -> str:
        bound = money(amount)
        if bound <= 0:
            raise ValueError("Positive charge bound required for metered hosted requests")
        with self.lock:
            state = self._read()
            if self.committed(state) + bound > self.cap:
                raise BudgetExceeded("study_cost_cap")
            request_id = uuid4().hex
            state["requests"].append(
                {
                    "reservation_id": request_id,
                    "reserved_usd": str(bound),
                    "state": "reserved",
                    "created_at": datetime.now(UTC).isoformat(),
                    **metadata,
                }
            )
            self._write(state)
        return request_id

    def settle(self, request_id: str, charged: float, metadata: dict[str, Any]) -> None:
        amount = money(charged)
        with self.lock:
            state = self._read()
            row = next(r for r in state["requests"] if r["reservation_id"] == request_id)
            if row["state"] != "reserved":
                raise ValueError("Reservation already finalized")
            row.update(metadata, charged_usd=str(amount), state="settled")
            self._write(state)
            if amount > money(row["reserved_usd"]) or self.committed(state) > self.cap:
                raise BudgetExceeded("provider_charge_exceeded_reservation")

    def fail(self, request_id: str, reason: str) -> None:
        with self.lock:
            state = self._read()
            row = next(r for r in state["requests"] if r["reservation_id"] == request_id)
            if row["state"] == "reserved":
                row.update(state="unknown_cost", reason=reason)
                self._write(
                    state
                )  # Full reservation remains consumed until audited reconciliation.

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            state = self._read()
        state["committed_usd"] = str(self.committed(state))
        state["settled_usd"] = str(
            sum(
                (money(r["charged_usd"]) for r in state["requests"] if r["state"] == "settled"),
                Decimal(0),
            )
        )
        return state
