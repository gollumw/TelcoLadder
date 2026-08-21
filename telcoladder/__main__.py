"""讓 `python -m telcoladder` 等同於 `telcoladder`。"""

from telcoladder.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
