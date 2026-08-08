"""Reject ELF binaries tracked by Git.

Build outputs belong in the ignored artifacts directory, not in source control.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ELF_MAGIC = b"\x7fELF"


def tracked_files(repository: Path) -> list[Path]:
    """Return paths currently present in the Git index."""
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repository,
        check=True,
        capture_output=True,
    )
    return [repository / item.decode() for item in result.stdout.split(b"\0") if item]


def find_tracked_elf_files(repository: Path) -> list[Path]:
    """Find indexed files whose contents start with the ELF magic bytes."""
    elf_files: list[Path] = []
    for path in tracked_files(repository):
        try:
            with path.open("rb") as stream:
                is_elf = stream.read(len(ELF_MAGIC)) == ELF_MAGIC
        except (FileNotFoundError, IsADirectoryError):
            # Staged deletions and unusual index entries have no worktree file to inspect.
            continue
        if is_elf:
            elf_files.append(path.relative_to(repository))
    return elf_files


def main() -> int:
    """Exit non-zero and list every tracked ELF binary."""
    repository = Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    elf_files = find_tracked_elf_files(repository)
    if not elf_files:
        print("No tracked ELF binaries found.")
        return 0

    print("Tracked ELF binaries are not allowed:")
    for path in elf_files:
        print(f"  - {path}")
    print("Store build outputs under artifacts/ instead.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
