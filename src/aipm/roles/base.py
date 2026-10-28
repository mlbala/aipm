"""The Role protocol (ARCHITECTURE §5.3): render a prompt, then validate the output."""

from typing import Protocol

from aipm.domain.models import RoleName
from aipm.llm.gateway import RenderedPrompt


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
