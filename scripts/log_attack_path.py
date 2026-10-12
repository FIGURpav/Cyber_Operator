"""CLI wrapper for attack-path transition logging."""

if __package__:
    from .operational_trace import attack_path_main
else:
    from operational_trace import attack_path_main


if __name__ == "__main__":
    raise SystemExit(attack_path_main())
