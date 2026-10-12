"""CLI wrapper for operational change lifecycle logging."""

if __package__:
    from .operational_trace import change_main
else:
    from operational_trace import change_main


if __name__ == "__main__":
    raise SystemExit(change_main())
