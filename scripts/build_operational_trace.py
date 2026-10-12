"""CLI wrapper for operational trace report generation."""

if __package__:
    from .operational_trace import build_main
else:
    from operational_trace import build_main


if __name__ == "__main__":
    raise SystemExit(build_main())
