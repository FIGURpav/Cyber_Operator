"""CLI wrapper for canonical report-contract and readiness operations."""

if __package__:
    from .screenshot_workflow import report_main
else:
    from screenshot_workflow import report_main


if __name__ == "__main__":
    raise SystemExit(report_main())
