"""Entry point for `docker exec -i <target> python seed_loader.py` (D-033, D-041)."""

import sys

from seed import main

if __name__ == "__main__":
    sys.exit(main())
