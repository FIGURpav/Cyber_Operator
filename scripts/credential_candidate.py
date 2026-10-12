"""Secret-free guards for credentials extracted from untrusted prose."""

AMBIGUOUS_BARE_SUFFIXES = frozenset(".,;:)]}")
QUOTE_STYLES = frozenset({"single-quoted", "double-quoted", "bare"})


def requires_boundary_confirmation(value: str, quote_style: str) -> bool:
    """Return whether a prose-derived token has an ambiguous right boundary.

    Credential intake must preserve exact secret bytes.  Therefore punctuation is
    never stripped here.  Instead, an unquoted token ending in common sentence or
    closing punctuation is withheld until an exact quoted/structured source or a
    successful validation establishes the intended boundary.
    """
    if quote_style not in QUOTE_STYLES:
        raise ValueError("unsupported credential quote style")
    return bool(
        quote_style == "bare"
        and value
        and value[-1] in AMBIGUOUS_BARE_SUFFIXES
    )
