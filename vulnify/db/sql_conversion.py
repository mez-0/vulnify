"""Shared SQLite value coercion for CVE read/write."""

from __future__ import annotations

from datetime import date, datetime, timezone


def dt_sentinel() -> datetime:
    """
    Get a sentinel datetime.

    :return: A sentinel datetime.
    :rtype: datetime
    """
    return datetime.min.replace(tzinfo=timezone.utc)


def datetime_to_sql(d: datetime) -> str | None:
    """
    Convert a datetime to a SQL string.

    :param d: The datetime to convert.
    :type d: datetime
    :return: The SQL string, or None when the datetime is invalid.
    :rtype: str | None
    """
    if d.year <= 1:
        return None
    return d.isoformat()


def sql_to_datetime(value: str | None) -> datetime:
    """
    Convert a SQL string to a datetime.

    :param value: The SQL string to convert.
    :type value: str | None
    :return: The datetime, or a sentinel datetime when the string is invalid.
    :rtype: datetime
    """
    if not value:
        return dt_sentinel()
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def date_to_sql(d: date) -> str | None:
    """
    Convert a date to a SQL string.

    :param d: The date to convert.
    :type d: date
    :return: The SQL string, or None when the date is invalid.
    :rtype: str | None
    """
    if d.year <= 1:
        return None
    return d.isoformat()


def sql_to_date(value: str | None) -> date:
    """
    Convert a SQL string to a date.

    :param value: The SQL string to convert.
    :type value: str | None
    :return: The date, or a sentinel date when the string is invalid.
    :rtype: date
    """
    if not value:
        return date.min
    return date.fromisoformat(value)


def bool_to_sql(b: bool) -> int:
    """
    Convert a boolean to a SQL integer.

    :param b: The boolean to convert.
    :type b: bool
    :return: The SQL integer, or 0 when the boolean is False.
    :rtype: int
    """
    return 1 if b else 0


def sql_to_bool(v: int | None) -> bool:
    """
    Convert a SQL integer to a boolean.

    :param v: The SQL integer to convert.
    :type v: int | None
    :return: The boolean, or False when the integer is None.
    :rtype: bool
    """
    return bool(v)


def bool_to_sql_nullable(b: bool | None) -> int | None:
    """
    Convert a tri-state boolean to a nullable SQL integer.

    Preserves the ``None`` ("not assessed") state rather than collapsing it to
    ``0`` — unlike :func:`bool_to_sql`.

    :param b: The tri-state boolean to convert.
    :type b: bool | None
    :return: 1/0 for True/False, or None when not assessed.
    :rtype: int | None
    """
    if b is None:
        return None
    return 1 if b else 0


def sql_to_bool_nullable(v: int | None) -> bool | None:
    """
    Convert a nullable SQL integer back to a tri-state boolean.

    :param v: The SQL integer to convert.
    :type v: int | None
    :return: True/False for 1/0, or None when the column is NULL.
    :rtype: bool | None
    """
    if v is None:
        return None
    return bool(v)
