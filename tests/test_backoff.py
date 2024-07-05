from datetime import datetime, timedelta
from time import time

import pytest

from zsuite import exponential_delay
from zsuite.backoff import (
    _apply_bounds,
    _normalize_cutoff,
    _normalize_jitter_pct,
    _validate_arguments,
)


def test_initial_conditions():
    with pytest.raises(ValueError):
        list(exponential_delay(minimum_sleep=0, enable_sleep=False))

    with pytest.raises(ValueError):
        list(exponential_delay(max_sleep=0, enable_sleep=False))

    with pytest.raises(ValueError):
        list(exponential_delay(backoff_factor=1, enable_sleep=False))


def test_jitter_conditions():
    with pytest.raises(ValueError):
        list(exponential_delay(jitter_pct=-1, enable_sleep=False))

    with pytest.raises(ValueError):
        list(exponential_delay(jitter_pct=101, enable_sleep=False))


def test_cutoff():
    total_delay = 1
    max_sleep = 0.25
    cutoff = datetime.now() + timedelta(seconds=total_delay)
    delays = list(exponential_delay(minimum_sleep=0.001, max_sleep=max_sleep, cutoff=cutoff))
    assert sum(delays) <= total_delay + max_sleep + max_sleep * 0.1


def test_max_attempts():
    delays = list(exponential_delay(minimum_sleep=1, max_sleep=10, max_attempts=3, enable_sleep=False))
    assert len(delays) == 3  # Should have 3 elements including the first 0


def test_minimum_sleep():
    delays = list(exponential_delay(minimum_sleep=1, jitter_pct=0.9, max_attempts=100, enable_sleep=False))
    assert delays[0] == 0  # The first sleep should be 0
    assert all(d >= 1 for d in delays[1:])  # All other sleeps should be >= 1


def test_maximum_sleep():
    delays = list(
        exponential_delay(
            minimum_sleep=1,
            max_sleep=10,
            jitter_pct=0.5,
            max_attempts=100,
            enable_sleep=False,
        )
    )
    assert delays[0] == 0  # The first sleep should be 0
    assert all(1 <= d <= 10 for d in delays[1:])  # All other sleeps should be >= 1


def test_first_sleep():
    first_sleep = next(exponential_delay(minimum_sleep=1, max_sleep=10))
    assert first_sleep == 0  # The first sleep should be 0


def test_backoff():
    max_attempts = 15
    delays = list(
        exponential_delay(
            minimum_sleep=0.1,
            jitter_pct=0.0,
            max_sleep=60,
            max_attempts=max_attempts,
            enable_sleep=False,
            backoff_factor=2,
        )
    )
    expected = [
        0,
        0.1,
        0.2,
        0.4,
        0.8,
        1.6,
        3.2,
        6.4,
        12.8,
        25.6,
        51.2,
        60,
        60,
        60,
        60,
    ]
    assert len(delays) == max_attempts
    assert delays == expected


# Tests for _normalize_jitter_pct function
def test_normalize_jitter_pct_with_int():
    assert _normalize_jitter_pct(10) == 0.1
    assert _normalize_jitter_pct(100) == 1.0
    assert _normalize_jitter_pct(0) == 0.0


def test_normalize_jitter_pct_with_float():
    assert _normalize_jitter_pct(0.1) == 0.1
    assert _normalize_jitter_pct(1.0) == 1.0
    assert _normalize_jitter_pct(0.0) == 0.0


def test_normalize_jitter_pct_with_invalid_int():
    with pytest.raises(ValueError):
        _normalize_jitter_pct(-1)
    with pytest.raises(ValueError):
        _normalize_jitter_pct(101)


def test_normalize_jitter_pct_with_invalid_float():
    with pytest.raises(ValueError):
        _normalize_jitter_pct(-0.1)
    with pytest.raises(ValueError):
        _normalize_jitter_pct(1.1)


# Tests for _normalize_cutoff function
def test_normalize_cutoff_with_datetime():
    dt = datetime.now()
    assert round(_normalize_cutoff(dt) - dt.timestamp(), 3) == 0.0


def test_normalize_cutoff_with_timedelta():
    td = timedelta(seconds=10)
    assert round(_normalize_cutoff(td) - (time() + td.total_seconds()), 3) == 0.0


def test_normalize_cutoff_with_int():
    assert round(_normalize_cutoff(10) - (time() + 10), 3) == 0.0


# Tests for _validate_arguments function
def test_validate_arguments_all_good():
    _validate_arguments(1.1, 1, 1, 0.1)  # Should not raise any exception


def test_validate_arguments_bad_minimum_sleep():
    with pytest.raises(ValueError, match="Initial sleep time must be greater than 0"):
        _validate_arguments(1.1, 1, 1, 0)


def test_validate_arguments_bad_max_sleep():
    with pytest.raises(ValueError, match="Maximum sleep time must be greater than 0"):
        _validate_arguments(1.1, 1, 0, 0.1)


def test_validate_arguments_bad_backoff_factor():
    with pytest.raises(ValueError, match="Backoff factor must be greater than 1"):
        _validate_arguments(1, 1, 1, 0.1)


def test_validate_arguments_bad_max_attempts():
    with pytest.raises(ValueError, match="If provided, max_attempts must be greater than 0"):
        _validate_arguments(1.1, 0, 1, 0.1)


# Tests for _apply_bounds function
def test_apply_bounds_within_range():
    assert _apply_bounds(5, 1, 10) == 5  # Inside the range, should return the value itself


def test_apply_bounds_equal_to_min():
    assert _apply_bounds(1, 1, 10) == 1  # Equal to minimum, should return the minimum


def test_apply_bounds_equal_to_max():
    assert _apply_bounds(10, 1, 10) == 10  # Equal to maximum, should return the maximum


def test_apply_bounds_below_min():
    assert _apply_bounds(0, 1, 10) == 1  # Below minimum, should return the minimum


def test_apply_bounds_above_max():
    assert _apply_bounds(11, 1, 10) == 10  # Above maximum, should return the maximum
