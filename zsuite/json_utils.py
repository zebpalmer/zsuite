"""JSON serialization utilities with extended type support."""

import json
from collections import deque
from datetime import datetime, timedelta

try:
    from bson import ObjectId
except ImportError:  # pymongo not installed
    ObjectId = None

__all__ = ["json_dump", "json_handler"]


def json_dump(raw):
    """Serialize object to JSON string with support for extended types.

    Wrapper around json.dumps() that handles types not natively JSON-serializable,
    including datetime, timedelta, MongoDB ObjectId, sets, deques, and objects with
    standard serialization methods.

    :param raw: Object to serialize to JSON. Can be any JSON-serializable type or
                extended types supported by json_handler.
    :type raw: any
    :returns: JSON string representation of the object.
    :rtype: str
    :raises TypeError: If object contains types not supported by json_handler.

    **Example:**

    .. code-block:: python

        # Standard types work as expected
        json_dump({"key": "value", "number": 42})
        # '{"key": "value", "number": 42}'

        # Extended types are automatically handled
        json_dump({"timestamp": datetime.now(), "roles": {"admin", "user"}})
        # '{"timestamp": "2024-03-15T14:30:00.123456", "roles": ["admin", "user"]}'

        # MongoDB ObjectId support
        json_dump({"_id": ObjectId("507f1f77bcf86cd799439011")})
        # '{"_id": "507f1f77bcf86cd799439011"}'
    """
    return json.dumps(raw, default=json_handler)


def json_handler(obj):
    """Custom JSON serializer for objects not natively JSON-serializable.

    Handles serialization for extended types by checking for standard conversion
    methods and applying appropriate transformations. Used as the default parameter
    for json.dumps().

    **Supported Types:**

    - datetime: Converted to ISO 8601 string via isoformat()
    - timedelta: Converted to total seconds (float)
    - MongoDB ObjectId: Converted to string representation
    - set/deque: Converted to list
    - Objects with isoformat() method: Calls isoformat()
    - Objects with json() method: Calls json()
    - Objects with to_json() method: Calls to_json()
    - Objects with to_dict() method: Calls to_dict()

    :param obj: Object to serialize.
    :type obj: any
    :returns: JSON-serializable representation of the object.
    :rtype: str | float | list | dict
    :raises TypeError: If object type is not supported and has no standard
                       serialization method.

    **Example:**

    .. code-block:: python

        # Datetime objects
        json_handler(datetime(2024, 3, 15, 14, 30))
        # '2024-03-15T14:30:00'

        # Timedelta objects
        json_handler(timedelta(hours=2, minutes=30))
        # 9000.0

        # Sets become lists
        json_handler({"admin", "user"})
        # ['admin', 'user']


        # Custom objects with to_dict()
        class User:
            def to_dict(self):
                return {"name": "john", "role": "admin"}


        json_handler(User())
        # {'name': 'john', 'role': 'admin'}

    .. note::
        This function checks serialization methods in a specific order:
        isoformat() → json() → to_json() → to_dict(). The first matching
        method is used.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, timedelta):
        return obj.total_seconds()
    elif ObjectId is not None and isinstance(obj, ObjectId):
        return str(obj)
    elif isinstance(obj, set | deque):
        return list(obj)
    elif hasattr(obj, "isoformat"):
        return obj.isoformat()
    elif hasattr(obj, "json"):
        return obj.json()
    elif hasattr(obj, "to_json"):
        return obj.to_json()
    elif hasattr(obj, "to_dict"):
        return obj.to_dict()
    else:
        raise TypeError(f"Object of type {type(obj)} with value of {obj} is not JSON serializable.")
