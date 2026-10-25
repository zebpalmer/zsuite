from collections import deque
from datetime import datetime, timedelta

import pytest
from bson import ObjectId

from zsuite.json_utils import json_handler


def test_datetime():
    dt = datetime.now()
    assert json_handler(dt) == dt.isoformat()


def test_timedelta():
    td = timedelta(days=1, seconds=1)
    assert json_handler(td) == 86401.0


def test_objectid():
    oid = ObjectId()
    assert json_handler(oid) == str(oid)


def test_set():
    s = {1, 2, 3}
    assert json_handler(s) == [1, 2, 3]


def test_deque():
    d = deque([1, 2, 3])
    assert json_handler(d) == [1, 2, 3]


def test_custom_isoformat_obj():
    class CustomDate:
        def isoformat(self):
            return "custom_date"

    assert json_handler(CustomDate()) == "custom_date"


def test_custom_json_obj():
    class CustomJSON:
        def json(self):
            return "custom_json"

    assert json_handler(CustomJSON()) == "custom_json"


def test_custom_to_json_obj():
    class CustomToJSON:
        def to_json(self):
            return "custom_to_json"

    assert json_handler(CustomToJSON()) == "custom_to_json"


def test_unsupported_type():
    with pytest.raises(TypeError):
        json_handler(complex(1, 1))


def test_json_handler_unserializable_raises():
    class Opaque:
        __slots__ = ()

    with pytest.raises(TypeError, match="not JSON serializable"):
        json_handler(Opaque())


def test_json_handler_to_dict_object():
    class WithToDict:
        def to_dict(self):
            return {"from": "to_dict"}

    assert json_handler(WithToDict()) == {"from": "to_dict"}
