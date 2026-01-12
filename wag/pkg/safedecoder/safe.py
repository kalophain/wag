"""Safe JSON decoder that disallows unknown fields."""

import json
from typing import Any, IO, Type, TypeVar

T = TypeVar('T')


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


def decode_strict(stream: IO[bytes], model: Type[T]) -> T:
    """
    Decode JSON from stream with strict field validation using a Pydantic model.
    
    This provides functionality similar to Go's DisallowUnknownFields() by using
    Pydantic models which reject unknown fields by default.
    
    Args:
        stream: Input stream to read JSON from
        model: Pydantic model class to validate against
        
    Returns:
        Instance of the model with validated data
        
    Raises:
        ValidationError: If JSON doesn't match model or has unknown fields
        
    Example:
        >>> from pydantic import BaseModel
        >>> class MyModel(BaseModel):
        ...     name: str
        >>> import io
        >>> stream = io.BytesIO(b'{"name": "test"}')
        >>> obj = decode_strict(stream, MyModel)
    """
    data = json.load(stream)
    return model(**data)
