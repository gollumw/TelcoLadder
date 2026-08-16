"""讓 `python -m telcolens` 等同於 `telcolens`。"""

from telcolens.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
