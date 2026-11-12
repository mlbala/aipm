"""Dependency checks for the go and rust-cargo stacks (build prompt 08, SECURITY.md §12.2).

`go.mod` and `Cargo.toml` are manifests: their direct dependencies must be declared in the
task's `deps_add`, and a source that bypasses the registry (a `replace`, a `git`, `path` or
other `registry` dependency, a `[patch]`, a new `toolchain`) is a violation. `go.sum` and
`Cargo.lock` are lockfiles: every new package is looked up, and a Cargo source other than
crates.io is a violation. Cargo and Go configuration files that can redirect a download or run a
program are package configuration.
"""

import pytest

from aipm.domain.models import (
    AcceptanceCriterion,
    ChangeSet,
    ChangeStatus,
    DependencyAdd,
    Ecosystem,
    FileChange,
    Task,
    TaskSize,
    TaskType,
)
from aipm.security.diff_checks import (
    CheckPolicy,
    Kind,
    check_changes,
    is_lockfile,
    is_manifest,
    is_package_config,
    lock_deps,
    manifest_deps,
    new_dependencies,
    new_lock_packages,
)

POLICY = CheckPolicy(test_roots=("tests",))
GO_MOD = """module example.com/clinic

go 1.24

require github.com/google/uuid v1.6.0 // indirect

require (
\tgithub.com/stretchr/testify v1.10.0
\t// a comment
\tgolang.org/x/sync v0.10.0 // indirect
)
"""
CARGO = """[package]
name = "clinic"
version = "0.1.0"

[dependencies]
serde = "1"
serde_json = { version = "1" }
local = { path = "crates/local" }
renamed = { package = "tokio", version = "1" }
shared = { workspace = true }

[dev-dependencies]
rand = "0.9"

[target.'cfg(unix)'.dependencies]
libc = "0.2"
"""


def task(*deps: tuple[Ecosystem, str], owns: tuple[str, ...] = ("go.mod", "Cargo.toml")) -> Task:
    return Task.model_validate({
        "id": "T-002", "title": "Slots", "type": TaskType.FEATURE,
        "owns_files": ["src/**", *owns],
        "acceptance": [AcceptanceCriterion(id="AC-T002-1", text="x")], "size": TaskSize.M,
        "deps_add": [DependencyAdd(ecosystem=e, name=n) for e, n in deps],
    })  # fmt: skip


def change(path: str, before: str | None, after: str | None, **kw: object) -> FileChange:
    status = ChangeStatus.ADDED if before is None else ChangeStatus.MODIFIED
    return FileChange(path=path, status=status, mode="100644", before=before, after=after, **kw)  # type: ignore[arg-type]


def violations(*changes: FileChange, t: Task | None = None) -> list[tuple[Kind, str]]:
    found = check_changes(ChangeSet("a" * 40, files=changes), t or task(), POLICY)
    return [(v.kind, v.detail) for v in found]


@pytest.mark.parametrize(
    ("path", "manifest", "lock", "config"),
    [
        ("go.mod", True, False, False),
        ("svc/GO.MOD", True, False, False),
        ("go.sum", True, True, False),
        ("Cargo.toml", True, False, False),
        ("Cargo.lock", True, True, False),
        ("go.work", False, False, True),
        ("go.work.sum", False, False, True),
        (".cargo/config.toml", False, False, True),
        ("crates/x/.cargo/config", False, False, True),
        ("rust-toolchain.toml", False, False, True),
        ("rust-toolchain", False, False, True),
        ("src/config.toml", False, False, False),
    ],
)
def test_path_classes(path: str, manifest: bool, lock: bool, config: bool) -> None:
    assert (is_manifest(path), is_lockfile(path), is_package_config(path)) == (
        manifest,
        lock,
        config,
    )


# ---------------------------------------------------------------- go.mod


def test_go_mod_direct_dependencies() -> None:
    deps = manifest_deps("go.mod", GO_MOD)
    assert deps is not None
    assert deps.names == {
        (Ecosystem.GO, "github.com/google/uuid"),
        (Ecosystem.GO, "github.com/stretchr/testify"),
        (Ecosystem.GO, "golang.org/x/sync"),
    }
    assert deps.off_registry == frozenset()


def test_an_undeclared_go_dependency_is_a_violation() -> None:
    after = GO_MOD.replace(")\n", "\tgithub.com/gin-gonic/gin v1.10.0\n)\n")
    found = violations(change("go.mod", GO_MOD, after))
    assert (Kind.DEPENDENCY, "go dependency github.com/gin-gonic/gin is not in deps_add") in found
    declared = task((Ecosystem.GO, "github.com/gin-gonic/gin"))
    assert violations(change("go.mod", GO_MOD, after), t=declared) == []


@pytest.mark.parametrize(
    ("added", "source"),
    [
        ("replace github.com/stretchr/testify => github.com/evil/testify v1.0.0\n",
         "github.com/stretchr/testify => github.com/evil/testify v1.0.0"),
        ("replace (\n\tgolang.org/x/sync => ../../elsewhere\n)\n",
         "golang.org/x/sync => ../../elsewhere"),
        ("replace golang.org/x/sync => /abs/path\n", "golang.org/x/sync => /abs/path"),
        ("toolchain go1.99.0\n", "toolchain go1.99.0"),
    ],
)  # fmt: skip
def test_a_go_source_outside_the_proxy_is_a_violation(added: str, source: str) -> None:
    found = violations(change("go.mod", GO_MOD, GO_MOD + added))
    assert (Kind.DEPENDENCY, f"source outside the registry: {source}") in found


def test_a_replace_inside_the_repository_is_fine() -> None:
    after = GO_MOD + "replace golang.org/x/sync => ./third_party/sync\n"
    assert violations(change("go.mod", GO_MOD, after)) == []


@pytest.mark.parametrize(
    "text",
    [
        "require (\n\tgithub.com/a/b v1\n",  # an unclosed block
        "require (\n\tgithub.com/a/b\n)\n",  # an entry with no version, in a block
        "require\n",  # a directive with nothing after it
        "require github.com/a/b\n",  # no version
        "x" * 5000 + "\n",
        "replace a =>\n",
    ],
)
def test_an_unreadable_go_mod_is_a_violation(text: str) -> None:
    assert manifest_deps("go.mod", text) is None
    assert (Kind.DEPENDENCY, "manifest cannot be read") in violations(
        change("go.mod", GO_MOD, text)
    )


# ---------------------------------------------------------------- Cargo.toml


def test_cargo_direct_dependencies() -> None:
    deps = manifest_deps("Cargo.toml", CARGO)
    assert deps is not None
    assert deps.names == {
        (Ecosystem.CRATES, n) for n in ("serde", "serde-json", "tokio", "shared", "rand", "libc")
    }
    assert deps.off_registry == frozenset()


def test_an_undeclared_crate_is_a_violation_and_dashes_match_underscores() -> None:
    after = CARGO.replace('rand = "0.9"', 'rand = "0.9"\nonce_cell = "1"')
    found = violations(change("Cargo.toml", CARGO, after))
    assert (Kind.DEPENDENCY, "crates dependency once-cell is not in deps_add") in found
    assert violations(change("Cargo.toml", CARGO, after),
                      t=task((Ecosystem.CRATES, "once_cell"))) == []  # fmt: skip


@pytest.mark.parametrize(
    ("added", "source"),
    [
        ('[dependencies.evil]\ngit = "https://example.com/evil.git"\n', "evil: git"),
        ('[build-dependencies]\nb = { path = "../outside" }\n', "b: path"),
        ('[build-dependencies]\nb = { version = "1", registry = "other" }\n', "b: registry"),
        ('[patch.crates-io]\nserde = { git = "https://example.com/serde" }\n', "patch serde"),
        ('[replace]\n"serde:1.0.0" = { path = "x" }\n', "replace serde:1.0.0"),
        ('[workspace.dependencies]\nw = { git = "https://example.com/w" }\n', "w: git"),
    ],
)
def test_a_cargo_source_outside_crates_io_is_a_violation(added: str, source: str) -> None:
    found = violations(change("Cargo.toml", CARGO, CARGO + added),
                       t=task((Ecosystem.CRATES, "evil"), (Ecosystem.CRATES, "b"),
                              (Ecosystem.CRATES, "w")))  # fmt: skip
    assert any(k is Kind.DEPENDENCY and source in d for k, d in found), found


def test_an_unreadable_cargo_toml_is_a_violation() -> None:
    assert manifest_deps("Cargo.toml", "[dependencies\n") is None
    assert manifest_deps("Cargo.toml", "dependencies = 3\n") is not None


def test_odd_cargo_tables_are_read_without_trusting_their_shape() -> None:
    deps = manifest_deps("Cargo.toml", "target = { odd = 1 }\npatch = { x = 2 }\n")
    assert deps is not None and deps.names == frozenset() and deps.off_registry == frozenset()


# ---------------------------------------------------------------- lockfiles

CARGO_LOCK = """version = 4

[[package]]
name = "clinic"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "itoa"
version = "1.0.11"
source = "sparse+https://index.crates.io/"
"""
GO_SUM = """github.com/stretchr/testify v1.10.0 h1:abc=
github.com/stretchr/testify v1.10.0/go.mod h1:def=
github.com/davecgh/go-spew v1.1.1/go.mod h1:ghi=
"""


def test_cargo_lock_packages_and_sources() -> None:
    locked = lock_deps("Cargo.lock", CARGO_LOCK)
    assert locked is not None
    assert locked.names == {(Ecosystem.CRATES, "serde"), (Ecosystem.CRATES, "itoa")}
    assert locked.sources == frozenset()
    git = CARGO_LOCK + '\n[[package]]\nname = "evil"\nversion = "1.0.0"\n' \
        'source = "git+https://example.com/evil#abc"\n'  # fmt: skip
    found = violations(change("Cargo.lock", CARGO_LOCK, git),
                       t=task((Ecosystem.CRATES, "evil"), owns=("Cargo.lock",)))  # fmt: skip
    assert any("evil: git+https://example.com/evil" in d for _, d in found), found


def test_go_sum_modules() -> None:
    locked = lock_deps("go.sum", GO_SUM)
    assert locked is not None
    assert locked.names == {
        (Ecosystem.GO, "github.com/stretchr/testify"),
        (Ecosystem.GO, "github.com/davecgh/go-spew"),
    }


@pytest.mark.parametrize("text", ["only-one-field\n", "a b c d\n", "x" * 5000 + " v1 h1:x\n"])
def test_an_unreadable_go_sum_is_a_violation(text: str) -> None:
    assert lock_deps("go.sum", text) is None


def test_new_lock_packages_are_listed_for_lookup() -> None:
    after = GO_SUM + "github.com/gin-gonic/gin v1.10.0 h1:x=\n"
    changes = ChangeSet("a" * 40, files=(change("go.sum", GO_SUM, after),))
    assert new_lock_packages(changes) == [("go.sum", Ecosystem.GO, "github.com/gin-gonic/gin")]
    cargo = CARGO_LOCK.replace('name = "itoa"', 'name = "ryu"')
    changes = ChangeSet("a" * 40, files=(change("Cargo.lock", CARGO_LOCK, cargo),))
    assert new_lock_packages(changes) == [("Cargo.lock", Ecosystem.CRATES, "ryu")]


def test_a_lockfile_is_in_scope_with_a_declared_dependency_of_its_ecosystem() -> None:
    after = GO_SUM + "github.com/gin-gonic/gin v1.10.0 h1:x=\n"
    declared = task((Ecosystem.GO, "github.com/gin-gonic/gin"), owns=())
    assert violations(change("go.sum", GO_SUM, after), t=declared) == []
    other = task((Ecosystem.CRATES, "serde"), owns=())
    assert (Kind.OUT_OF_SCOPE, "outside the files T-002 owns") in violations(
        change("go.sum", GO_SUM, after), t=other
    )


@pytest.mark.parametrize("path", ["go.work", ".cargo/config.toml", "rust-toolchain.toml"])
def test_package_configuration_is_a_violation(path: str) -> None:
    found = violations(change(path, None, "x\n"), t=task(owns=(path,)))
    assert any(k is Kind.DEPENDENCY and "package manager configuration" in d for k, d in found)


def test_new_dependencies_read_both_manifests() -> None:
    files = (
        change("go.mod", None, GO_MOD),
        change("Cargo.toml", None, CARGO),
    )
    found = new_dependencies(ChangeSet("a" * 40, files=files))
    assert ("go.mod", Ecosystem.GO, "github.com/stretchr/testify") in found
    assert ("Cargo.toml", Ecosystem.CRATES, "serde-json") in found
