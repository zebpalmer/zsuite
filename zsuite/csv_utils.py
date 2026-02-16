"""CSV file import and export utilities"""

import csv
from pathlib import Path

from .file_utils import ensure_recent_file, find_data_file, remove_if_exists


def import_csv_data(
    filename: str | Path,
    max_stale: int | None = 7,
    mode: str = "r",
    encoding: str = "utf-8-sig",
) -> list[dict]:
    """Import CSV file and convert to list of dictionaries with freshness validation.

    :param filename: Name or Path of the CSV file to import.
    :type filename: str | Path
    :param max_stale: Maximum age in days before file is considered stale. Set to None or 0
                      to disable freshness check.
    :type max_stale: int | None
    :param mode: File mode for opening the CSV file.
    :type mode: str
    :param encoding: Encoding of the CSV file. Defaults to 'utf-8-sig' to handle BOM.
    :type encoding: str
    :returns: List of dictionaries representing rows in the CSV, with headers as keys.
    :rtype: list[dict]
    """
    path = filename if isinstance(filename, Path) else find_data_file(filename)

    if max_stale is not None and max_stale > 0:
        ensure_recent_file(path, days=max_stale)
    return csv_to_dict(path, mode=mode, encoding=encoding)


def output_csv(rows, filename):
    """Write rows to a CSV file, replacing any existing file.

    :param rows: List of lists/tuples representing rows to write.
    :type rows: list
    :param filename: Path where the CSV file should be written.
    :type filename: str | Path
    """
    remove_if_exists(filename)
    with Path(filename).open("w", encoding="utf-8") as csvfile:
        csvwriter = csv.writer(csvfile)
        for row in rows:
            csvwriter.writerow(row)


def output_dicts_to_csv(rows, headers, filename, ignore_extra_fields=False, **kwargs):
    """Write list of dictionaries to a CSV file with specified headers.

    :param rows: List of dictionaries to write as CSV rows.
    :type rows: list[dict]
    :param headers: List of field names to use as CSV headers.
    :type headers: list[str]
    :param filename: Path where the CSV file should be written.
    :type filename: str | Path
    :param ignore_extra_fields: If True, silently ignore dictionary keys not in headers.
    :type ignore_extra_fields: bool
    :param kwargs: Additional keyword arguments passed to csv.DictWriter.
    """
    remove_if_exists(filename)

    options = {
        "fieldnames": headers,
        "dialect": "excel",
        "extrasaction": "ignore" if ignore_extra_fields else "raise",
    }
    for k, w in kwargs.items():
        options[k] = w

    with Path(filename).open("w", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, **options)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def csv_to_dict(
    path: str | Path,
    mode="r",
    encoding="utf-8-sig",
    lowercase_headers: bool = False,
    skip_lines: int = 0,
    max_stale: int | None = None,
    **dictreader_kwargs,
):
    """Read CSV file and convert to list of dictionaries.

    :param path: Path to the CSV file.
    :type path: str | Path
    :param mode: File mode for opening the CSV file.
    :type mode: str
    :param encoding: Encoding of the CSV file. Defaults to 'utf-8-sig' to handle BOM.
    :type encoding: str
    :param lowercase_headers: If True, converts all header names to lowercase.
    :type lowercase_headers: bool
    :param skip_lines: Number of lines to skip at the beginning of the file.
    :type skip_lines: int
    :param max_stale: Maximum age in days before file is considered stale.
    :type max_stale: int | None
    :param dictreader_kwargs: Additional keyword arguments passed to csv.DictReader.
    :returns: List of dictionaries representing rows in the CSV.
    :rtype: list[dict]
    """
    if isinstance(path, str):
        path = Path(path)

    if max_stale is not None and max_stale > 0:
        ensure_recent_file(path, days=max_stale)

    with path.open(mode=mode, encoding=encoding) as csvfile:
        for _ in range(skip_lines):
            next(csvfile)

        reader = csv.DictReader(csvfile, **dictreader_kwargs)

        if lowercase_headers and reader.fieldnames:
            reader.fieldnames = [field.lower().strip() for field in reader.fieldnames]

        return list(reader)


def import_multiple_csv(path=None, pattern="*"):
    """Import and combine multiple CSV files matching a pattern.

    :param path: Directory path to search for CSV files. Uses current directory if None.
    :type path: str | Path | None
    :param pattern: Glob pattern for matching files. Defaults to '*' (all files).
    :type pattern: str
    :returns: Combined list of dictionaries from all matching CSV files.
    :rtype: list[dict]
    """
    data = []
    paths = list(Path(path).rglob(pattern))
    for p in paths:
        if p.is_file():
            data.extend(csv_to_dict(p.absolute()))
    return data
