"""CLI wrapper for canonical report-contract and readiness operations."""

if __package__:
    from .screenshot_workflow import report_main
else:
    from screenshot_workflow import report_main


if __name__ == "__main__":
    import sys

    if len(sys.argv)>1 and sys.argv[1] in {'build','readiness','snapshot'}:
        if __package__:
            from .assessment_reporting import main
        else:
            from assessment_reporting import main
        raise SystemExit(main(sys.argv[1:]))
    raise SystemExit(report_main())
