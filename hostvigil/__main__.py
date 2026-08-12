"""Allow running HostVigil as a module: python -m hostvigil"""

import sys
from pathlib import Path

# Ensure the project root is on the path so `run.main()` works
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


def _main():
    from run import main

    sys.exit(main())


if __name__ == "__main__":
    _main()
