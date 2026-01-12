"""Command infrastructure for Wag."""

from abc import ABC, abstractmethod
from typing import Optional


class Command(ABC):
    """Base class for all Wag commands."""
    
    @abstractmethod
    def name(self) -> str:
        """Return the command name."""
        pass
    
    @abstractmethod
    def check(self) -> Optional[str]:
        """Check if command can be run. Return error message if not."""
        pass
    
    @abstractmethod
    async def run(self):
        """Execute the command."""
        pass
    
    @abstractmethod
    def print_usage(self):
        """Print usage information."""
        pass
