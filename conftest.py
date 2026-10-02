import sys
from pathlib import Path

# Automatically add project root to sys.path for pytest discovery
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))
