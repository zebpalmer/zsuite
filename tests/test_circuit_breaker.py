import time

import pytest

from zsuite import CircuitBreaker
from zsuite.exceptions import CircuitBreakerTripped


def test_increment():
    cb = CircuitBreaker(max_events=3, time_window=1)
    for _ in range(3):
        cb.increment()
    assert cb.count() == 3
    with pytest.raises(CircuitBreakerTripped):
        cb.increment()


def test_reset():
    cb = CircuitBreaker(max_events=3, time_window=1)
    cb.increment()
    assert cb.count() == 1
    cb.reset()
    assert cb.count() == 0


def test_time_window():
    cb = CircuitBreaker(max_events=3, time_window=1)
    cb.increment()
    assert cb.count() == 1
    time.sleep(1.1)  # Sleep to exceed the time window
    assert cb.count() == 0


def test_custom_exception():
    custom_exc = ValueError
    cb = CircuitBreaker(max_events=1, time_window=1, custom_exception=custom_exc)
    with pytest.raises(custom_exc):
        cb.increment()
        cb.increment()


def test_initialization_fails():
    with pytest.raises(ValueError):
        CircuitBreaker(max_events=None, time_window=1)
    with pytest.raises(ValueError):
        CircuitBreaker(max_events=3, time_window=None)
