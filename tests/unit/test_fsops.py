"""Tests for fsops module."""

import tempfile
import os
from pathlib import Path
from wag.pkg.fsops import copy_file


def test_copy_file():
    """Test file copying functionality."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create source file
        src = Path(tmpdir) / "source.txt"
        src.write_text("test content")
        
        # Copy to destination
        dst = Path(tmpdir) / "dest.txt"
        copy_file(src, dst)
        
        # Verify content
        assert dst.read_text() == "test content"
        
        # Verify metadata preserved
        assert src.stat().st_mode == dst.stat().st_mode


if __name__ == "__main__":
    test_copy_file()
    print("✓ All fsops tests passed")
