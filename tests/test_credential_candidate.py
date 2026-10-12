import pytest

from scripts.credential_candidate import requires_boundary_confirmation


@pytest.mark.parametrize("suffix", [".", ",", ";", ":", ")", "]", "}"])
def test_bare_candidate_with_prose_boundary_is_ambiguous(suffix: str) -> None:
    assert requires_boundary_confirmation(f"FictionalValue{suffix}", "bare")


@pytest.mark.parametrize("style", ["single-quoted", "double-quoted"])
def test_quoted_punctuation_is_preserved_as_exact(style: str) -> None:
    assert not requires_boundary_confirmation("FictionalValue.", style)


def test_common_password_punctuation_is_not_silently_changed() -> None:
    assert not requires_boundary_confirmation("FictionalValue!", "bare")


def test_unknown_quote_style_fails_closed() -> None:
    with pytest.raises(ValueError, match="unsupported credential quote style"):
        requires_boundary_confirmation("FictionalValue", "unknown")
