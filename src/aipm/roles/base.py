"""The Role protocol (ARCHITECTURE §5.3) and the one way roles render their prompts.

Role templates live in `aipm/roles/prompts/` and are rendered only through the sandboxed,
fail-closed environment from `aipm.security.untrusted`: every piece of text aipm did not write
itself reaches a prompt as `Untrusted`, through the `|untrusted` filter, inside a block with a
fresh nonce (SECURITY.md §7.2).
"""

from collections.abc import Mapping
from typing import Protocol

from aipm import roles as _package
from aipm.domain.models import RoleName
from aipm.llm.gateway import RenderedPrompt
from aipm.security.untrusted import NonceFactory, PackageTemplateLoader, make_env


class Role[In, Out](Protocol):
    """A tool-less LLM role."""

    name: RoleName
    template_version: str
    output_schema: type[Out]

    def render(self, inp: In) -> RenderedPrompt:
        """Render the prompt; untrusted parts are pre-wrapped."""
        ...

    def postprocess(self, out: Out, inp: In) -> Out:
        """Apply deterministic validation to the model output."""
        ...


def render_prompt(
    role: RoleName, context: Mapping[str, object], *, nonce: NonceFactory | None = None
) -> RenderedPrompt:
    """Render `<role>.system.j2` and `<role>.user.j2` from the package templates."""
    loader = PackageTemplateLoader(_package, "prompts")
    env = make_env(loader) if nonce is None else make_env(loader, nonce=nonce)
    system = env.get_template(f"{role.value}.system.j2").render(**context)
    user = env.get_template(f"{role.value}.user.j2").render(**context)
    return RenderedPrompt(system=system, user=user)
