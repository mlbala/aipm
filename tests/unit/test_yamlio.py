"""Deterministic YAML, front matter and the `.pm/` layout (ARCHITECTURE §6.1, §6.2)."""

import io
import os
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from aipm.domain.errors import SchemaError, UsageError
from aipm.domain.models import ArtifactKind
from aipm.state import frontmatter
from aipm.state.layout import artifact_name, artifact_path, pm_root, repo_id
from aipm.state.yamlio import MAX_YAML_BYTES, dump_yaml, load_yaml
from tests.fakes.secrets import FAKE_SECRETS

CORPUS = Path(__file__).parents[1] / "security" / "corpus"

# ---------------------------------------------------------------- load


def test_load_keeps_plain_types_and_order() -> None:
    data = load_yaml("b: 1\na: [x, {c: null}]\nflag: true\n")
    assert data == {"b": 1, "a": ["x", {"c": None}], "flag": True}
    assert isinstance(data, dict)
    assert list(data) == ["b", "a", "flag"]  # pyright: ignore[reportUnknownArgumentType]


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("a: &x 1\nb: *x\n", "anchors"),
        ("a: *x\n", "aliases|not valid"),
        ("a: &x [1]\n", "anchors"),
        ("a: !!python/object/apply:os.system [id]\n", "tags"),
        ("a: !custom 1\n", "tags"),
        ("a: !!str 1\n", "tags"),
        ("--- !!map\na: 1\n", "tags"),
        ("a: 1\na: 2\n", "not valid YAML"),
        ("a: 1\n---\nb: 2\n", "not valid YAML"),
        ("a: [1, 2\n", "not valid YAML"),
        ("[" * 65 + "]" * 65, "deeper than 64"),
    ],
)
def test_load_rejects(text: str, match: str) -> None:
    with pytest.raises(SchemaError, match=match):
        load_yaml(text, source="t.yaml")


def test_load_rejects_files_over_one_mib() -> None:
    with pytest.raises(SchemaError, match="larger than 1 MiB"):
        load_yaml("a: " + "x" * MAX_YAML_BYTES)


def test_error_messages_never_echo_the_input() -> None:
    secret = FAKE_SECRETS["OPENAI_API_KEY"]
    with pytest.raises(SchemaError) as info:
        load_yaml(f"key: [{secret}\n", source="t.yaml")
    assert secret not in info.value.message
    assert "line" in info.value.message


def test_corpus_alias_bomb_is_rejected_before_expansion() -> None:
    case = YAML(typ="safe", pure=True).load(
        (CORPUS / "C-011-structural-yaml-alias-bomb.yaml").read_text(encoding="utf-8")
    )
    with pytest.raises(SchemaError, match="anchors") as info:
        load_yaml(case["input"]["text"], source=".pm/config.yaml")
    assert int(info.value.exit_code) == case["expected"]["exit_code"]


# ---------------------------------------------------------------- dump


def test_dump_is_deterministic_and_ordered() -> None:
    data = {"schema_version": 1, "z": "yes", "a": ["x", {"k": "v"}], "n": None, "t": True}
    first, second = dump_yaml(data), dump_yaml(dict(data))
    assert first == second
    assert first.endswith("\n")
    assert first.splitlines()[:2] == ["schema_version: 1", "z: yes"]
    assert "n: null" in first
    assert load_yaml(first) == data


def test_dump_writes_multiline_strings_as_literal_blocks() -> None:
    text = dump_yaml({"description": "line one\nline two\n"})
    assert text == "description: |\n  line one\n  line two\n"
    assert load_yaml(text) == {"description": "line one\nline two\n"}


def test_dump_quotes_strings_that_would_change_type() -> None:
    data = {"a": "0123", "b": "true", "c": "null", "d": "1.5", "e": "- x", "f": "a: b"}
    assert load_yaml(dump_yaml(data)) == data


@pytest.mark.parametrize("value", ["word " * 60, "ab " * 90, "two  spaces  " * 30, "x" * 300])
def test_dump_folds_long_strings_without_changing_them(value: str) -> None:
    text = dump_yaml({"long": value})
    assert load_yaml(text) == {"long": value}
    if value.startswith(("word", "ab")):
        assert len(text.splitlines()) > 2
        assert max(len(line) for line in text.splitlines()) <= 104  # ruamel's best effort


def test_dump_does_not_change_ruamel_globally() -> None:
    out = io.StringIO()
    YAML(typ="rt", pure=True).dump({"n": None}, out)
    assert out.getvalue() == "n:\n"


# ---------------------------------------------------------------- front matter


def test_front_matter_round_trip() -> None:
    text = frontmatter.dump({"schema_version": 1, "kind": "prd"}, "# Title\n\nBody.\n")
    assert text == "---\nschema_version: 1\nkind: prd\n---\n# Title\n\nBody.\n"
    assert frontmatter.parse(text) == ({"schema_version": 1, "kind": "prd"}, "# Title\n\nBody.\n")


@pytest.mark.parametrize(
    ("text", "body"),
    [
        ("---\na: 1\n---", ""),
        ("---\na: 1\n---\n", ""),
        ("---\r\na: 1\r\n---\r\nbody\r\n", "body\n"),
        ("---\na: 1\n---\nx\n---\ny\n", "x\n---\ny\n"),
    ],
)
def test_front_matter_edges(text: str, body: str) -> None:
    assert frontmatter.parse(text) == ({"a": 1}, body)


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("# no front matter\n", "missing"),
        ("---\na: 1\n", "not closed"),
        ("---\n- a\n---\n", "mapping"),
        ("---\n---\n", "mapping"),
        ("---\na: &x 1\n---\n", "anchors"),
    ],
)
def test_front_matter_rejects(text: str, match: str) -> None:
    with pytest.raises(SchemaError, match=match):
        frontmatter.parse(text)


# ---------------------------------------------------------------- layout


def test_layout_paths(tmp_path: Path) -> None:
    assert pm_root(tmp_path) == tmp_path / ".pm"
    assert artifact_path(tmp_path, ArtifactKind.THREAT_MODEL) == tmp_path / ".pm/threat-model.md"
    assert artifact_name(ArtifactKind.REPO_MAP) == "repo-map.md"
    with pytest.raises(UsageError, match="adr"):
        artifact_name(ArtifactKind.ADR)


def test_repo_id_hashes_the_real_path(tmp_path: Path) -> None:
    real = tmp_path / "repo"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    assert repo_id(real) == repo_id(link)
    assert len(repo_id(real)) == 16
    assert repo_id(real) != repo_id(tmp_path)
    assert all(ch in "0123456789abcdef" for ch in repo_id(Path(os.sep)))
