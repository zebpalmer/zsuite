from datetime import date, datetime, timezone
from unittest.mock import patch
from zoneinfo import ZoneInfo

import pytest

from zsuite import fuzzy_bool, now_utc, parse_timestamp
from zsuite.exceptions import UndeterminedBool


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
    with patch("zsuite.timestamps.datetime") as mock_datetime:
        mock_datetime.now.return_value = datetime(2022, 1, 1, tzinfo=timezone.utc)
        result = now_utc(naive=False)
        assert result == datetime(2022, 1, 1, tzinfo=timezone.utc)


def test_now_utc_naive():
    with patch("zsuite.timestamps.datetime") as mock_datetime:
        mock_datetime.now.return_value = datetime(2022, 1, 1, tzinfo=timezone.utc)
        result = now_utc(naive=True)
        assert result == datetime(2022, 1, 1).replace(tzinfo=None)


def test_now_utc():
    ts = now_utc()
    assert isinstance(ts, datetime)
    ts_naive = now_utc(naive=False)
    assert isinstance(ts_naive, datetime)


def test_parse_timestamp_from_date():
    input_date = date(2024, 2, 26)
    expected_datetime = datetime(2024, 2, 26, tzinfo=ZoneInfo("UTC"))
    assert parse_timestamp(input_date) == expected_datetime


def test_parse_timestamp_from_naive_datetime():
    input_datetime = datetime(2024, 2, 26, 15, 30)
    expected_datetime = datetime(2024, 2, 26, 15, 30, tzinfo=ZoneInfo("UTC"))
    assert parse_timestamp(input_datetime) == expected_datetime


def test_parse_timestamp_from_aware_datetime():
    input_datetime = datetime(2024, 2, 26, 15, 30, tzinfo=ZoneInfo("Europe/Paris"))
    expected_datetime = input_datetime.astimezone(ZoneInfo("UTC"))
    assert parse_timestamp(input_datetime) == expected_datetime


def test_parse_timestamp_with_different_timezone():
    input_date = date(2024, 2, 26)
    expected_datetime = datetime(2024, 2, 26, tzinfo=ZoneInfo("America/New_York"))
    assert parse_timestamp(input_date, output_tz="America/New_York") == expected_datetime


def test_parse_timestamp_from_string():
    result = parse_timestamp("2024-02-26")
    expected = datetime(2024, 2, 26, tzinfo=ZoneInfo("UTC"))
    assert result == expected


def test_parse_timestamp_from_string_with_time():
    result = parse_timestamp("2024-02-26 15:30:00")
    expected = datetime(2024, 2, 26, 15, 30, tzinfo=ZoneInfo("UTC"))
    assert result == expected


def test_parse_timestamp_from_string_with_input_tz():
    result = parse_timestamp("2024-02-26 15:30:00", input_tz="America/Chicago")
    assert result.tzinfo is not None
    assert result == datetime(2024, 2, 26, 15, 30, tzinfo=ZoneInfo("America/Chicago")).astimezone(ZoneInfo("UTC"))


def test_parse_timestamp_raises_type_error():
    with pytest.raises(TypeError):
        parse_timestamp(12345)


def test_parse_timestamp_raises_value_error_empty():
    with pytest.raises(ValueError):
        parse_timestamp("")


def test_parse_timestamp_raises_value_error_invalid():
    with pytest.raises(ValueError):
        parse_timestamp("not a date")
