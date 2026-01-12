"""Thread-safe bounded queue implementation."""

import threading
from typing import Generic, TypeVar, List

T = TypeVar('T')


class Queue(Generic[T]):
    """
    A thread-safe bounded queue that maintains a maximum number of items.
    New items are added to the front, and oldest items are dropped when the queue is full.
    """
    
    def __init__(self, max_size: int):
        """
        Initialize the queue with a maximum size.
        
        Args:
            max_size: Maximum number of items the queue can hold
        """
        self._lock = threading.Lock()
        self._max = max_size
        self._items: List[T] = []
    
    def write(self, item: T) -> tuple[int, None]:
        """
        Add an item to the front of the queue.
        If the queue is full, the oldest item is removed.
        
        Args:
            item: Item to add to the queue
            
        Returns:
            Tuple of (1, None) indicating one item was written
        """
        with self._lock:
            if len(self._items) >= self._max:
                # Remove oldest item (at the end)
                self._items = self._items[:-1]
            
            # Add new item to the front
            self._items.insert(0, item)
            
        return (1, None)
    
    def read_all(self) -> List[T]:
        """
        Read all items from the queue without removing them.
        
        Returns:
            List of all items in the queue
        """
        with self._lock:
            return self._items.copy()
