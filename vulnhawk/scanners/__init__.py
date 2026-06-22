"""Auto-import all scanner modules for plugin discovery."""

from importlib import import_module
from pathlib import Path

# Auto-import all scanner modules in this directory
_scanners_dir = Path(__file__).parent
for _scanner_file in _scanners_dir.glob("*.py"):
    if _scanner_file.name.startswith("_"):
        continue
    import_module(f"vulnhawk.scanners.{_scanner_file.stem}")
