"""Test package: makes ``src/`` importable for unittest discovery.

Usage (from the repository root):

    python -m unittest discover -s tests -t .
"""

import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
