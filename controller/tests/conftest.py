import sys
from pathlib import Path

# Keep existing flat fixture imports alongside the explicit tests.* package.
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).parents[2] / "analysis" / "src"))
sys.path.insert(0, str(Path(__file__).parents[2] / "sensor" / "worker" / "src"))
