"""Property test (§20): the redactor never outputs a registered fake secret (invariant I-5)."""

from hypothesis import given, settings
from hypothesis import strategies as st

from aipm.security.redact import Redactor
from tests.fakes.secrets import FAKE_SECRETS

VALUES = sorted(FAKE_SECRETS.values())
# Fragments of the secrets as well as whole values, so near-misses and overlaps are tried.
PIECES = st.one_of(
    st.sampled_from(VALUES),
    st.sampled_from(VALUES).map(lambda v: v[: len(v) // 2]),
    st.sampled_from(VALUES).map(lambda v: v[len(v) // 2 :]),
    st.sampled_from(["token: ", "api_key=", "Bearer ", "«", "»", "REDACTED", ":", "\n", " "]),
    st.text(max_size=8),
)


@settings(max_examples=500)
@given(st.lists(PIECES, max_size=30).map("".join))
def test_redactor_never_outputs_a_registered_fake_secret(text: str) -> None:
    out = Redactor(dict(FAKE_SECRETS)).redact(text)
    for value in VALUES:
        assert value not in out
