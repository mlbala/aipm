"""An in-memory keychain for tests (ADR-0033). It records every account it is asked for."""

from dataclasses import dataclass, field


@dataclass
class FakeKeychain:
    """`aipm.config.keychain.Backend` over a dict; `fail` makes every lookup raise."""

    items: dict[str, str] = field(default_factory=dict[str, str])
    asked: list[str] = field(default_factory=list[str])
    fail: bool = False
    label: str = "fake keychain"

    def get(self, account: str) -> str | None:
        self.asked.append(account)
        if self.fail:
            raise OSError("keychain locked")
        return self.items.get(account)

    def store(self, account: str, value: str) -> None:
        if self.fail:
            raise OSError("keychain locked")
        self.items[account] = value
