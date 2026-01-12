"""Safe JSON decoder that disallows unknown fields."""

import json
from typing import IO, TypeVar

T = TypeVar("T")


def decoder(stream: IO[bytes]) -> json.JSONDecoder:
    """
    Create a JSON decoder that operates on a stream.

    Note: Python's json.load() doesn't have a built-in option to disallow
    unknown fields like Go's DisallowUnknownFields(). This would need to be
    implemented with custom validation using Pydantic or similar libraries
    if strict field validation is required.

    Args:
        stream: Input stream to read JSON from

    Returns:
        A JSON decoder instance

    Example:
        >>> import io
        >>> stream = io.BytesIO(b'{"key": "value"}')
        >>> dec = decoder(stream)
        >>> # Use json.load(stream) to decode
    """
    return json.JSONDecoder()


def decode_strict(stream: IO[bytes], model: type[T]) -> T:
    """
    Decode JSON from stream with validation using a model/dataclass.

    Note: This is a basic implementation that validates against Python
    dataclasses or simple classes. For strict field validation that
    rejects unknown fields, integrate with Pydantic models which provide
    this functionality by default.

    Args:
        stream: Input stream to read JSON from
        model: Model class (dataclass, Pydantic model, etc.) to validate against

    Returns:
        Instance of the model with validated data

    Raises:
        TypeError: If data doesn't match model signature
        ValueError: If JSON is invalid

    Example:
        >>> from dataclasses import dataclass
        >>> @dataclass
        ... class MyModel:
        ...     name: str
        >>> import io
        >>> stream = io.BytesIO(b'{"name": "test"}')
        >>> obj = decode_strict(stream, MyModel)
    """
    data = json.load(stream)
    return model(**data)
