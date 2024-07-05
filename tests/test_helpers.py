from datetime import date, datetime, timezone
from unittest.mock import patch
from zoneinfo import ZoneInfo

import pytest

from zsuite.exceptions import UndeterminedBool
from zsuite.helpers import (
    fuzzy_bool,
    normalize_timestamp,
    now_utc,
)


def test_fuzzy_bool():
    cases = [
        (True, True),
        (False, False),
        ("True", True),
        ("False", False),
        ("T", True),
        ("F", False),
        ("", None),
        (1, True),
        (0, False),
        ("Yes", True),
        ("No", False),
        ("active", True),
        ("inactive", False),
        ("Enabled", True),
        ("Disabled", False),
    ]
    for testcase, expected in cases:
        assert fuzzy_bool(testcase) is expected

    badcases = []
    for x in badcases:
        with pytest.raises(UndeterminedBool):
            fuzzy_bool(x)


def test_now_utc_not_naive():
    with patch("zsuite.helpers.datetimes.datetime") as mock_datetime:
        mock_datetime.now.return_value = datetime(2022, 1, 1, tzinfo=timezone.utc)
        result = now_utc(naive=False)
        assert result == datetime(2022, 1, 1, tzinfo=timezone.utc)


def test_now_utc_naive():
    with patch("zsuite.helpers.datetimes.datetime") as mock_datetime:
        mock_datetime.now.return_value = datetime(2022, 1, 1, tzinfo=timezone.utc)
        result = now_utc(naive=True)
        assert result == datetime(2022, 1, 1).replace(tzinfo=None)


def test_now_utc():
    ts = now_utc()
    assert isinstance(ts, datetime)
    ts_naive = now_utc(naive=False)
    assert isinstance(ts_naive, datetime)


def test_normalize_from_date():
    input_date = date(2024, 2, 26)
    expected_datetime = datetime(2024, 2, 26, tzinfo=ZoneInfo("UTC"))
    assert normalize_timestamp(input_date) == expected_datetime


def test_normalize_from_naive_datetime():
    input_datetime = datetime(2024, 2, 26, 15, 30)
    expected_datetime = datetime(2024, 2, 26, 15, 30, tzinfo=ZoneInfo("UTC"))
    assert normalize_timestamp(input_datetime) == expected_datetime


def test_normalize_from_aware_datetime():
    input_datetime = datetime(2024, 2, 26, 15, 30, tzinfo=ZoneInfo("Europe/Paris"))
    expected_datetime = input_datetime.astimezone(ZoneInfo("UTC"))
    assert normalize_timestamp(input_datetime) == expected_datetime


def test_normalize_with_different_timezone():
    input_date = date(2024, 2, 26)
    expected_datetime = datetime(2024, 2, 26, tzinfo=ZoneInfo("America/New_York"))
    assert normalize_timestamp(input_date, tz="America/New_York") == expected_datetime


def test_normalize_raises_type_error():
    with pytest.raises(TypeError):
        normalize_timestamp("2024-02-26")  # passing a string instead of a date/datetime
