"""CLI wrapper for impact authorization logging."""

if __package__:
    from .operational_trace import authorization_main
else:
    from operational_trace import authorization_main


if __name__ == "__main__":
    raise SystemExit(authorization_main())
