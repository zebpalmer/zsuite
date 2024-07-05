from datetime import date, datetime, time, timezone
from zoneinfo import ZoneInfo


def now_utc(naive: bool = False) -> datetime:
    """Returns the current datetime in UTC timezone.

    :param naive: Optional; if True, the returned datetime will be naive. Default is False.
                  Use naive=True only when you need to interface with systems that expect naive datetime objects.
    :return: The current datetime in UTC timezone.
    """
    if naive:
        # Use only when interfacing with systems that require naive datetime objects
        return datetime.now(timezone.utc).replace(tzinfo=None)
    else:
        return datetime.now(timezone.utc)


def normalize_timestamp(raw, tz="UTC") -> datetime:
    """Return a datetime object with timezone information from various inputs
    :param raw: datetime, or timestamp
    :param tz: timezone
    :return: datetime
    """
    """
        Converts a date or datetime object to a timezone-aware datetime object.
        If the input is a date, it defaults to midnight.
        Timezone defaults to UTC if not specified.

        Args:
        input_date (date or datetime): The date or datetime to be converted.
        timezone (str, optional): The timezone to be applied. Defaults to 'UTC'.

        Returns:
        datetime: Timezone-aware datetime object.
        """
    if isinstance(raw, datetime):
        # If it's already a datetime, use it directly
        output_datetime = raw
    elif isinstance(raw, date):
        # If it's a date, convert to a datetime at midnight
        output_datetime = datetime.combine(raw, time(0, 0, 0))
    else:
        raise TypeError("Input must be a date or datetime object")

    # Attach timezone information
    if output_datetime.tzinfo is None:
        output_datetime = output_datetime.replace(tzinfo=ZoneInfo(tz))
    else:
        # Convert to the specified timezone if different from the input's timezone
        output_datetime = output_datetime.astimezone(ZoneInfo(tz))

    return output_datetime
