"""Run the LLM Security Lab CLI with `python -m llmsec`."""

from __future__ import annotations

import sys

from .cli import main


if __name__ == "__main__":
    sys.exit(main())
