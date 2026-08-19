"""讓 `python -m telcoshark` 等同於 `telcoshark`。"""

from telcoshark.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
