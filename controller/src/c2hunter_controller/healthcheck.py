"""Container health probe for the Controller HTTP process."""

from __future__ import annotations

from urllib.request import urlopen


def main() -> None:
    with urlopen("http://127.0.0.1:8000/api/v1/health", timeout=3) as response:
        if response.status != 200:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
