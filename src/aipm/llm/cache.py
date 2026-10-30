"""The LLM response cache under `.pm/cache/llm/` (v0.2; review 01, D-4; ARCHITECTURE §14).

**Key.** `sha256` over the canonical JSON of (provider, model, role, template version, rendered
prompt, schema JSON). In the rendered prompt each untrusted block's random nonce is replaced by
its ordinal, so an unchanged prompt keys the same; the prompt that is sent keeps its nonces.

**Determinism rule.** The gateway sends no sampling parameters, so the model is not
deterministic: the cache is what makes a rerun on unchanged input repeatable. Only the roles
whose callers ask for that pass a template version, and so read and write the cache: today the
AC reviewer, so the same diff gets the same verdict. A rerun of `discover`, `design` or `plan`
asks for a new answer and never reads it. `--no-cache` neither reads nor writes.

**Trust.** An entry is T2 like any other LLM output: on every read it is validated against the
role's schema again and goes through the role's `postprocess`; an entry that fails is deleted
and fetched again. Entries are written through the state store, so they are redacted.
"""

import hashlib
import json
from typing import Protocol

from aipm.security.untrusted import normalize_nonces

KEY_VERSION = 1


def cache_key(
    *,
    provider: str,
    model: str,
    role: str,
    template_version: str,
    rendered_prompt: str,
    schema_json: str,
) -> str:
    """Return the cache key from ARCHITECTURE §14."""
    payload = {
        "v": KEY_VERSION,
        "provider": provider,
        "model": model,
        "role": role,
        "template_version": template_version,
        "prompt": normalize_nonces(rendered_prompt),
        "schema": schema_json,
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


class ResponseCache(Protocol):
    """Where cached replies live (`FileStateStore` implements it)."""

    def cache_get(self, key: str) -> str | None:
        """The cached reply text for `key`, or `None`."""
        ...

    def cache_put(self, key: str, text: str) -> None:
        """Store the reply text for `key`."""
        ...

    def cache_drop(self, key: str) -> None:
        """Delete the entry for `key` (it failed validation)."""
        ...
