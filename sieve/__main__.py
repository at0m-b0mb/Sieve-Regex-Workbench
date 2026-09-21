"""python -m sieve — the command line, or the window when given no command."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
