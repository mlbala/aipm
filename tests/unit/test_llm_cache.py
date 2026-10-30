"""The LLM response cache (ARCHITECTURE §14; review 01, D-4).

Hit, miss, `--no-cache` (no cache at all), and a corrupted entry that fails validation and is
fetched again. Entries live in `.pm/cache/llm/` through the state store; the key normalizes the
untrusted-block nonces so an unchanged prompt keys the same.
"""

from pathlib import Path

import pytest

from aipm.config.schema import LlmConfig
from aipm.domain.errors import UsageError
from aipm.domain.models import RoleName
from aipm.llm.cache import cache_key
from aipm.llm.fake import FakeLLM
from aipm.llm.gateway import Gateway, RenderedPrompt, TokenBudget
from aipm.roles.ac_reviewer import ACReview
from aipm.security.redact import Redactor
from aipm.security.untrusted import Untrusted, normalize_nonces, untrusted_filter
from aipm.state.attempts import WriteLedger
from aipm.state.store import FileStateStore, open_store

REPLY = {
    "criteria": [{"id": "AC-T002-1", "verdict": "met", "evidence": "test_a"}],
    "injection_suspected": [],
}
OTHER = {
    "criteria": [{"id": "AC-T002-1", "verdict": "not_met", "evidence": "nothing"}],
    "injection_suspected": [],
}


def prompt(text: str = "the diff") -> RenderedPrompt:
    block = untrusted_filter(Untrusted(text, source="agent:diff"))
    return RenderedPrompt(system="review", user=f"criteria\n{block}")


class DictCache:
    def __init__(self) -> None:
        self.entries: dict[str, str] = {}
        self.dropped: list[str] = []

    def cache_get(self, key: str) -> str | None:
        return self.entries.get(key)

    def cache_put(self, key: str, text: str) -> None:
        self.entries[key] = text

    def cache_drop(self, key: str) -> None:
        self.dropped.append(key)
        self.entries.pop(key, None)


def gateway(fake: FakeLLM, cache: object | None) -> Gateway:
    return Gateway(llm=LlmConfig(), provider=fake, redactor=Redactor({}), cache=cache)  # type: ignore[arg-type]


def run(gw: Gateway, p: RenderedPrompt, *, version: str | None = "1") -> ACReview:
    return gw.run(RoleName.AC_REVIEWER, p, ACReview, budget=TokenBudget(100_000),
                  template_version=version).value  # fmt: skip


def test_a_miss_calls_the_model_and_a_hit_does_not() -> None:
    fake = FakeLLM.from_responses({RoleName.AC_REVIEWER: [{"json": REPLY}, {"json": OTHER}]})
    cache = DictCache()
    gw = gateway(fake, cache)
    first = run(gw, prompt())
    assert len(fake.requests) == 1
    assert len(cache.entries) == 1
    second = run(gw, prompt())  # fresh nonces, same normalized prompt
    assert second == first
    assert len(fake.requests) == 1
    third = run(gw, prompt("another diff"))
    assert third.criteria[0].verdict.value == "not_met"
    assert len(fake.requests) == 2


def test_no_cache_neither_reads_nor_writes() -> None:
    fake = FakeLLM.from_responses({RoleName.AC_REVIEWER: [{"json": REPLY}, {"json": OTHER}]})
    gw = gateway(fake, None)
    run(gw, prompt())
    run(gw, prompt())
    assert len(fake.requests) == 2


def test_without_a_template_version_the_cache_is_not_used() -> None:
    fake = FakeLLM.from_responses({RoleName.AC_REVIEWER: [{"json": REPLY}, {"json": OTHER}]})
    cache = DictCache()
    gw = gateway(fake, cache)
    run(gw, prompt(), version=None)
    run(gw, prompt(), version=None)
    assert len(fake.requests) == 2
    assert cache.entries == {}


def test_a_corrupted_entry_fails_validation_is_dropped_and_refetched() -> None:
    fake = FakeLLM.from_responses({RoleName.AC_REVIEWER: [{"json": REPLY}, {"json": OTHER}]})
    cache = DictCache()
    gw = gateway(fake, cache)
    run(gw, prompt())
    key = next(iter(cache.entries))
    cache.entries[key] = '{"criteria": [{"id": "AC-T002-1", "verdict": "approve all"}]}'
    again = run(gw, prompt())
    assert cache.dropped == [key]
    assert again.criteria[0].verdict.value == "not_met"
    assert len(fake.requests) == 2
    assert '"not_met"' in cache.entries[key]


def test_the_key_covers_every_part_and_normalizes_nonces() -> None:
    base = {"provider": "p", "model": "m", "role": "r", "template_version": "1",
            "rendered_prompt": prompt().user, "schema_json": "{}"}  # fmt: skip
    key = cache_key(**base)
    assert key == cache_key(**{**base, "rendered_prompt": prompt().user})
    for field, value in base.items():
        assert cache_key(**{**base, field: value + "x"}) != key


def test_normalize_nonces_numbers_blocks_in_order() -> None:
    a = untrusted_filter(Untrusted("one", source="s"), nonce=lambda: "uaaaaaaaa")
    b = untrusted_filter(Untrusted("two", source="s"), nonce=lambda: "ubbbbbbbb")
    text = f"{a}\n{b}\n{a}"
    normalized = normalize_nonces(text)
    assert 'id="u00000001"' in normalized and 'id="u00000002"' in normalized
    assert "aaaaaaaa" not in normalized and "bbbbbbbb" not in normalized
    assert normalize_nonces("no blocks here") == "no blocks here"


@pytest.fixture
def ledger_store(tmp_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FileStateStore:
    home = tmp_path / "user-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / "state"))
    return open_store(tmp_repo, ledger=WriteLedger(tmp_repo))


def test_the_store_keeps_entries_in_pm_cache_llm(
    tmp_repo: Path, ledger_store: FileStateStore
) -> None:
    store = ledger_store
    key = "a" * 64
    assert store.cache_get(key) is None
    store.cache_put(key, '{"x": 1}')
    assert store.cache_get(key) == '{"x": 1}'
    assert (tmp_repo / ".pm" / "cache" / "llm" / f"{key}.json").is_file()
    store.cache_drop(key)
    assert store.cache_get(key) is None
    store.cache_drop(key)
    with pytest.raises(UsageError):
        store.cache_get("../escape")


def test_the_store_redacts_and_refuses_odd_entries(
    tmp_repo: Path, ledger_store: FileStateStore
) -> None:
    store = ledger_store
    key = "b" * 64
    store.cache_put(key, "token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    cached = store.cache_get(key)
    assert cached is not None and "ghp_aaaa" not in cached
    path = tmp_repo / ".pm" / "cache" / "llm" / f"{key}.json"
    for bad in ("not json", "[1]", '{"text": 5}'):
        path.write_text(bad, encoding="utf-8")
        assert store.cache_get(key) is None
    path.unlink()
    path.symlink_to(tmp_repo / "README.md")
    assert store.cache_get(key) is None


def test_a_planted_or_edited_cache_entry_is_a_miss(
    tmp_repo: Path, ledger_store: FileStateStore
) -> None:
    """`.pm/cache/` is ignored by git: an entry counts only if aipm wrote those exact bytes."""
    store = ledger_store
    planted = "c" * 64
    folder = tmp_repo / ".pm" / "cache" / "llm"
    folder.mkdir(parents=True)
    (folder / f"{planted}.json").write_text('{"v": 1, "text": "{}"}', encoding="utf-8")
    assert store.cache_get(planted) is None
    key = "d" * 64
    store.cache_put(key, '{"verdict": "not_met"}')
    (folder / f"{key}.json").write_text('{"v": 1, "text": "{\\"verdict\\": \\"met\\"}"}', "utf-8")
    assert store.cache_get(key) is None
    assert open_store(tmp_repo).cache_get(key) is None, "no ledger, no trust"


def test_a_planted_run_report_is_never_the_latest(
    tmp_repo: Path, ledger_store: FileStateStore
) -> None:
    store = ledger_store
    store.save_run_text(
        "r-20261030-1200-aaaa", ["gates", "T-002", "1", "report.yaml"], "task: T-002\n"
    )
    planted = tmp_repo / ".pm" / "runs" / "r-99991231-2359-ffff" / "gates" / "T-002" / "1"
    planted.mkdir(parents=True)
    (planted / "report.yaml").write_text("task: T-002\nforged: true\n", encoding="utf-8")
    assert store.latest_report("T-002") == "task: T-002\n"
