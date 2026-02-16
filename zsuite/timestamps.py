"""Timestamp parsing and timezone-aware datetime utilities."""

from datetime import date, datetime, time, timezone
from zoneinfo import ZoneInfo

from dateutil import parser as dateutil_parser


def now_utc(naive: bool = False) -> datetime:
    """Returns the current datetime in UTC timezone.

    :param naive: If True, returns a naive datetime (no timezone info). Use only when
                  interfacing with systems that require naive datetime objects.
    :type naive: bool
    :returns: Current datetime in UTC timezone, timezone-aware unless naive=True.
    :rtype: datetime
    """
    if naive:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    else:
        return datetime.now(timezone.utc)


def parse_timestamp(raw: str | date | datetime, output_tz: str = "UTC", input_tz: str | None = None) -> datetime:
    """Parse and normalize timestamps from strings, dates, or datetime objects.

    Convenience function that dispatches to the appropriate handler based on input type.
    For strings, uses dateutil.parser. For date/datetime objects, uses _normalize_timestamp.

    :param raw: String, date, or datetime to be converted.
    :type raw: str | date | datetime
    :param output_tz: Target timezone for the result.
    :type output_tz: str
    :param input_tz: For string inputs without timezone info, timezone to assume.
                     If None, naive timestamps are treated as output_tz.
    :type input_tz: str | None
    :returns: Timezone-aware datetime object in the specified output timezone.
    :rtype: datetime
    :raises ValueError: If string cannot be parsed as a valid timestamp.
    :raises TypeError: If input type is not supported (must be str, date, or datetime).

    **Examples:**

    .. code-block:: python

        parse_timestamp("2024-03-15 14:30:00")
        parse_timestamp(date(2024, 3, 15))
        parse_timestamp(datetime(2024, 3, 15, 14, 30))
        parse_timestamp("2024-03-15 14:30:00", input_tz="America/Chicago")
    """
    if isinstance(raw, str):
        return _parse_timestamp_string(raw, output_tz=output_tz, input_tz=input_tz)
    elif isinstance(raw, date | datetime):
        return _normalize_timestamp(raw, tz=output_tz)
    else:
        raise TypeError(f"Input must be a string, date, or datetime object, got {type(raw).__name__}")


def epoch_to_utc(epoch: str | float | int) -> datetime:
    """Convert epoch timestamp to UTC-aware datetime object.

    :param epoch: Epoch timestamp as string, float or int (seconds since Unix epoch).
    :type epoch: str | float | int
    :returns: UTC-aware datetime object.
    :rtype: datetime
    """
    if isinstance(epoch, str):
        epoch = float(epoch)
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def _normalize_timestamp(raw, tz="UTC") -> datetime:
    """Convert a date or datetime object to a timezone-aware datetime in the specified timezone.

    If the input is a date, it is converted to datetime at midnight. If the input datetime
    is naive, the specified timezone is attached. If timezone-aware, it is converted to
    the target timezone.
    """
    if isinstance(raw, datetime):
        output_datetime = raw
    elif isinstance(raw, date):
        output_datetime = datetime.combine(raw, time(0, 0, 0))
    else:
        raise TypeError("Input must be a date or datetime object")

    if output_datetime.tzinfo is None:
        output_datetime = output_datetime.replace(tzinfo=ZoneInfo(tz))
    else:
        output_datetime = output_datetime.astimezone(ZoneInfo(tz))

    return output_datetime


def _parse_timestamp_string(timestamp_str: str, output_tz: str = "UTC", input_tz: str | None = None) -> datetime:
    """Parse a timestamp string and return a normalized timezone-aware datetime.

    Internal function - use parse_timestamp() for the public API.
    """
    if not isinstance(timestamp_str, str):
        raise TypeError(f"Input must be a string, got {type(timestamp_str).__name__}")

    if not timestamp_str.strip():
        raise ValueError("Input string cannot be empty")

    try:
        parsed_dt = dateutil_parser.parse(timestamp_str)

        if parsed_dt.tzinfo is None and input_tz is not None:
            parsed_dt = parsed_dt.replace(tzinfo=ZoneInfo(input_tz))

        return _normalize_timestamp(parsed_dt, tz=output_tz)

    except (ValueError, dateutil_parser.ParserError) as e:
        raise ValueError(f"Unable to parse timestamp string '{timestamp_str}': {e}") from e
