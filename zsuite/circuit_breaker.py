import time
from collections import deque

from .exceptions import CircuitBreakerTripped


class CircuitBreaker:
    def __init__(self, max_events: int = None, time_window: int = None, custom_exception=None):
        if max_events is None:
            raise ValueError("max_events must be set")
        if time_window is None:
            raise ValueError("time_window must be set")
        self.max_events = max_events
        self.time_window = time_window
        self._exception_type = custom_exception if custom_exception else CircuitBreakerTripped
        self._event_timestamps = deque()

    def increment(self, current_exception=None):
        if self.count() >= self.max_events:
            if current_exception:
                raise CircuitBreakerTripped(
                    f"Circuit Breaker tripped at max events: {current_exception}"
                ) from current_exception
            else:
                raise self._exception_type("Circuit Breaker tripped at max events") from None

        else:
            self._event_timestamps.append(time.time())

    def reset(self):
        self._event_timestamps.clear()

    def count(self):
        self._remove_old_events()
        return len(self._event_timestamps)

    def _remove_old_events(self):
        current_time = time.time()
        while self._event_timestamps and current_time - self._event_timestamps[0] > self.time_window:
            self._event_timestamps.popleft()
