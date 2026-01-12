"""Tests for queue module."""

from wag.pkg.queue import Queue


def test_queue_basic():
    """Test basic queue operations."""
    q = Queue[int](max_size=3)
    
    # Add items
    count, err = q.write(1)
    assert count == 1
    assert err is None
    
    count, err = q.write(2)
    assert count == 1
    
    count, err = q.write(3)
    assert count == 1
    
    # Read all
    items = q.read_all()
    assert items == [3, 2, 1]  # FIFO with newest first


def test_queue_overflow():
    """Test queue behavior when full."""
    q = Queue[str](max_size=2)
    
    q.write("first")
    q.write("second")
    q.write("third")  # Should drop "first"
    
    items = q.read_all()
    assert items == ["third", "second"]
    assert "first" not in items


def test_queue_thread_safety():
    """Test that queue is thread-safe."""
    import threading
    
    q = Queue[int](max_size=100)
    
    def writer(start):
        for i in range(start, start + 10):
            q.write(i)
    
    threads = [
        threading.Thread(target=writer, args=(0,)),
        threading.Thread(target=writer, args=(10,)),
        threading.Thread(target=writer, args=(20,)),
    ]
    
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    items = q.read_all()
    assert len(items) == 30


if __name__ == "__main__":
    test_queue_basic()
    test_queue_overflow()
    test_queue_thread_safety()
    print("✓ All queue tests passed")
