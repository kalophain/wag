"""File copy operations."""

import shutil
from pathlib import Path


def copy_file(src: str | Path, dst: str | Path) -> None:
    """
    Copy a file from src to dst.

    Args:
        src: Source file path
        dst: Destination file path

    Raises:
        FileNotFoundError: If source file doesn't exist
        PermissionError: If lacking permissions to read/write
        OSError: For other OS-level errors
    """
    shutil.copy2(src, dst)
