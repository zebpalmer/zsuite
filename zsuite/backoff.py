from datetime import datetime, timedelta
from random import uniform
from time import sleep, time


def exponential_delay(
    minimum_sleep: int | float = 0.1,
    max_sleep: int | float = 60,
    jitter_pct: int | float = 0.1,
    backoff_factor: float = 1.25,
    cutoff: datetime | timedelta | int | None = None,
    max_attempts: int | None = None,
    enable_sleep: bool = True,
):
    """
    Generates sleep times based on exponential backoff algorithm.

    NOTE: First sleep is always 0 seconds. This is to allow the caller to perform an initial action before sleeping.

    Parameters:
    - minimum_sleep (float): The initial sleep time in seconds. Must be greater than 0.
    - max_sleep (float): The maximum sleep time in seconds. Must be greater than 0.
    - backoff_factor (float): The multiplier applied to the current sleep time to get the next sleep time.
    - jitter_pct (int | float): Optional jitter percentage to apply.
        - If int, should be between 0 and 100.
        - If float, should be between 0 and 1.
    - cutoff (datetime | timedelta | int | None): Optional cutoff time for the sleep.
        - If datetime, uses the given datetime as the cutoff.
        - If timedelta, adds the delta to the current time to get the cutoff.
        - If int, adds the number of seconds to the current time to get the cutoff.
    - enable_sleep (bool): Whether to actually sleep for the generated sleep times. Useful for testing.

    Yields:
    - sleep_time (float): The next sleep time in seconds.

    Raises:
    - ValueError: If any of the parameters are out of their valid range.

    Examples::

    for sleep_time in exponential_delay(initial_sleep=0.1, max_sleep=10, backoff_factor=1.15):
        print(f"Slept for {sleep_time} seconds")


    """
    current_delay = minimum_sleep
    count = 1

    # Validate & normalize arguments
    _validate_arguments(backoff_factor, max_attempts, max_sleep, minimum_sleep)
    cutoff = _normalize_cutoff(cutoff)
    jitter_pct = _normalize_jitter_pct(jitter_pct)

    # Main loop

    yield 0  # Always yield at least once, and the first sleep should be 0
    while True:
        count += 1
        if max_attempts is not None and count > max_attempts:
            return
        if cutoff and time() >= cutoff:
            return  # stop iteration if we've reached the cutoff time

        this_sleep = current_delay  # only apply jitter to the current sleep
        if jitter_pct:
            this_sleep = _apply_jitter(this_sleep, jitter_pct, minimum_sleep, max_sleep)
        this_sleep = _apply_bounds(this_sleep, minimum_sleep, max_sleep)

        if cutoff and time() + this_sleep > cutoff:
            this_sleep = cutoff - time()

        # Sleep (assuming it isn't disabled) and yield the sleep time
        if enable_sleep:
            sleep(this_sleep)  # sleep before yielding the slept time
        yield this_sleep

        if current_delay < max_sleep:
            current_delay *= backoff_factor
        current_delay = min(current_delay, max_sleep)


def _normalize_jitter_pct(jitter_pct):
    match jitter_pct:
        case int():
            if jitter_pct < 0 or jitter_pct > 100:
                raise ValueError("Jitter must be  int between 0 and 100 or float between 0 and 1")
            jitter_pct = float(jitter_pct * 0.01)
        case float():
            if jitter_pct < 0 or jitter_pct > 1:
                raise ValueError("Jitter must be float between 0 and 1, or int between 0 and 100")
    return jitter_pct


def _normalize_cutoff(cutoff):
    match cutoff:
        case datetime():
            cutoff = cutoff.timestamp()
        case timedelta():
            cutoff = time() + cutoff.total_seconds()
        case int():
            cutoff = cutoff + time()
    return cutoff


def _validate_arguments(backoff_factor, max_attempts, max_sleep, minimum_sleep):
    if minimum_sleep <= 0:
        raise ValueError("Initial sleep time must be greater than 0")
    if max_sleep <= 0:
        raise ValueError("Maximum sleep time must be greater than 0")
    if backoff_factor <= 1:
        raise ValueError("Backoff factor must be greater than 1")
    if max_attempts is not None and max_attempts <= 0:
        raise ValueError("If provided, max_attempts must be greater than 0")


def _apply_bounds(this_sleep, minimum_sleep, max_sleep):
    if this_sleep < minimum_sleep:
        this_sleep = minimum_sleep
    if this_sleep > max_sleep:
        this_sleep = max_sleep
    return this_sleep


def _apply_jitter(this_sleep, jitter_pct, minimum_sleep, max_sleep):
    upper = this_sleep + this_sleep * jitter_pct
    lower = this_sleep - this_sleep * jitter_pct
    if lower < minimum_sleep:
        lower = minimum_sleep
    if upper > max_sleep:
        upper = max_sleep
    this_sleep += uniform(
        lower,
        upper,
    )
    return this_sleep
