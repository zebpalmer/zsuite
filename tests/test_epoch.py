from datetime import datetime, timezone

import pytest

from zsuite.helpers.datetimes import epoch_to_utc


def test_epoch_to_utc():
    """Test epoch_to_utc with various input types and values"""
    # Reference datetime for comparison (2023-11-19 20:00:00 UTC)
    expected = datetime(2023, 11, 19, 20, 0, 0, tzinfo=timezone.utc)
    epoch = 1700424000  # Correct timestamp for 2023-11-19 20:00:00 UTC

    # Test integer input
    assert epoch_to_utc(epoch) == expected

    # Test float input
    assert epoch_to_utc(float(epoch)) == expected

    # Test string input
    assert epoch_to_utc(str(epoch)) == expected


def test_epoch_to_utc_subsecond():
    """Test handling of subsecond precision"""
    # Reference datetime with microseconds (2023-11-19 20:00:00.123456 UTC)
    expected = datetime(2023, 11, 19, 20, 0, 0, 123456, tzinfo=timezone.utc)
    epoch = 1700424000.123456  # Correct timestamp with subseconds

    # Test float with subsecond precision
    assert epoch_to_utc(epoch) == expected

    # Test string with subsecond precision
    assert epoch_to_utc(str(epoch)) == expected


def test_epoch_to_utc_invalid():
    """Test error handling for invalid inputs"""
    with pytest.raises(ValueError):
        epoch_to_utc("not a number")

    with pytest.raises(TypeError):
        epoch_to_utc([])  # wrong type

    with pytest.raises(TypeError):
        epoch_to_utc(None)  # None not allowed


def test_epoch_to_utc_edge_cases():
    """Test edge cases"""
    # Test zero (Unix epoch start)
    assert epoch_to_utc(0) == datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    # Test negative timestamp (pre-1970)
    assert epoch_to_utc(-1000) == datetime(1969, 12, 31, 23, 43, 20, tzinfo=timezone.utc)

    # Test very large timestamp
    future = 32503680000  # Year 3000
    assert epoch_to_utc(future).year == 3000
