"""
Shared pytest setup for the sensor tests. Run them all from this directory:

    python3 -m pytest

The sensors import each other as top-level modules (as they do when systemd
runs them from this directory), so the directory goes on the import path.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
