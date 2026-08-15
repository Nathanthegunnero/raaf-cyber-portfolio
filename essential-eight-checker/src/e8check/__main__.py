"""Allow ``python -m e8check``."""

from e8check.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
