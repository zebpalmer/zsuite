"""File operations utilities."""

import logging
from datetime import datetime, timedelta
from pathlib import Path

from .config import config_var
from .exceptions import FileNotFound, StaleFile

DATA_FILE_PATHS = [Path.cwd(), Path("../data"), Path("./data")]


def remove_if_exists(fpath: Path | str) -> bool:
    """Remove a file if it exists.

    Attempts to delete the file at the given path. Returns status indicating whether
    the file was successfully removed.

    :param fpath: Path to the file to remove.
    :type fpath: Path | str
    :returns: True if file was removed, False if file didn't exist.
    :rtype: bool
    """
    fpath = Path(fpath)
    try:
        fpath.unlink()
    except FileNotFoundError:
        return False
    else:
        return True


def _build_file_status_dict(fpath: Path) -> dict:
    """Build a dictionary containing file and parent directory status information.

    :param fpath: Path to the file to inspect.
    :type fpath: Path
    :returns: Dictionary with keys including file_path, is_absolute, file_exists,
              file_readable, file_writable, parent_dir_exists, etc.
    :rtype: dict
    """
    fpath = Path(fpath)
    status_dict = {}

    status_dict["file_path"] = str(fpath)
    status_dict["is_absolute"] = fpath.is_absolute()
    status_dict["absolute_path"] = str(fpath.resolve())
    status_dict["file_exists"] = fpath.is_file()
    status_dict["file_readable"] = fpath.exists() and fpath.stat().st_mode & 0o444 != 0
    status_dict["file_writable"] = fpath.exists() and fpath.stat().st_mode & 0o222 != 0
    status_dict["file_executable"] = fpath.exists() and fpath.stat().st_mode & 0o111 != 0
    status_dict["file_is_directory"] = fpath.is_dir()

    parent_dir = fpath.parent
    status_dict["parent_dir_exists"] = parent_dir.exists()
    status_dict["parent_dir_writable"] = parent_dir.exists() and parent_dir.stat().st_mode & 0o222 != 0
    status_dict["parent_dir_readable"] = parent_dir.exists() and parent_dir.stat().st_mode & 0o444 != 0

    return status_dict


def _print_file_status(status_dict: dict, force_print: bool = False) -> None:
    """Format and print or log file status information.

    :param status_dict: Dictionary containing file status information from
                        _build_file_status_dict.
    :type status_dict: dict
    :param force_print: If True, prints to console regardless of debug settings.
    :type force_print: bool
    """
    debug_info = []
    debug_info.extend(
        (
            f"\n---------------------------\nFILE DEBUG for: {status_dict['file_path']}",
            f"Path is absolute: {'Yes' if status_dict['is_absolute'] else 'No'}",
            f"Absolute path: {status_dict['absolute_path']}",
            f"File exists: {'Yes' if status_dict['file_exists'] else 'No'}",
            f"File is readable: {'Yes' if status_dict['file_readable'] else 'No'}",
            f"File is writable: {'Yes' if status_dict['file_writable'] else 'No'}",
            f"File is executable: {'Yes' if status_dict['file_executable'] else 'No'}",
            f"File is a directory: {'Yes' if status_dict['file_is_directory'] else 'No'}",
            f"Parent directory exists: {'Yes' if status_dict['parent_dir_exists'] else 'No'}",
            f"Parent directory is writable: {'Yes' if status_dict['parent_dir_writable'] else 'No'}",
            f"Parent directory is readable: {'Yes' if status_dict['parent_dir_readable'] else 'No'}",
            "\n---------------------------\n",
        )
    )

    combined_debug_message = "\n".join(debug_info)

    should_debug = config_var("DEBUG_FILE_PATH", False) or config_var("LOG_LEVEL", "INFO") == "DEBUG"

    if should_debug:
        log_level = config_var("LOG_LEVEL", "INFO")
        getattr(logging, log_level.lower())(combined_debug_message)

    if force_print:
        print(combined_debug_message)


def debug_file_path(fpath: Path | str, force_print: bool = False) -> dict:
    """Collect and display comprehensive file status information for debugging.

    :param fpath: Path to the file to debug.
    :type fpath: Path | str
    :param force_print: If True, prints status to console regardless of debug settings.
    :type force_print: bool
    :returns: Dictionary containing detailed file status information.
    :rtype: dict
    """
    fpath = Path(fpath)
    status_dict = _build_file_status_dict(fpath)
    _print_file_status(status_dict, force_print)
    return status_dict


def find_file(target_file: Path | str, locations: list[Path | str]) -> Path:
    """Search for a file in specified directories and return its absolute path.

    :param target_file: Name or path of the file to find.
    :type target_file: Path | str
    :param locations: List of directories to search for the file.
    :type locations: list[Path | str]
    :returns: Absolute path to the file.
    :rtype: Path
    :raises FileNotFound: If file not found in any of the specified locations.
    """
    target_file = Path(target_file)

    if target_file.exists():
        return target_file.resolve()

    for location in locations:
        location_path = Path(location) / target_file
        if location_path.exists():
            return location_path.resolve()

    raise FileNotFound(f"File '{target_file}' not found in any of the specified locations.")


def ensure_recent_file(target: Path | str, days: int = 7) -> bool:
    """Verify that a file was modified within the specified number of days.

    :param target: Path to the file to check.
    :type target: Path | str
    :param days: Maximum age in days for the file to be considered recent.
    :type days: int
    :returns: True if file is recent enough.
    :rtype: bool
    :raises StaleFile: If file is older than the specified number of days.
    """
    if not isinstance(target, Path):
        target = Path(target)

    if days is not None and not is_file_recent(target, days=days):
        raise StaleFile(f"ERROR: {target} is older than {days} days")

    return True


def is_file_recent(target: Path | str, days: int = 7) -> bool:
    """Check if a file was modified within the specified number of days.

    :param target: Path to the file to check.
    :type target: Path | str
    :param days: Maximum age in days for the file to be considered recent.
    :type days: int
    :returns: True if file was modified within the last 'days' days, False otherwise.
    :rtype: bool
    """
    target = Path(target)
    recent = datetime.now() - timedelta(days=days)
    ts_modified = datetime.fromtimestamp(target.stat().st_mtime)
    return ts_modified > recent


def find_data_file(target_file: Path | str) -> Path:
    """Locate a data file using predefined search locations.

    Convenience wrapper around find_file that searches common data file locations
    defined in DATA_FILE_PATHS (current directory, ../data, ./data).

    :param target_file: Name or path of the data file to find.
    :type target_file: Path | str
    :returns: Absolute path to the data file.
    :rtype: Path
    :raises FileNotFound: If file not found in any data file location.
    """
    config_var("DATA_PATH", DATA_FILE_PATHS)
    return find_file(target_file, locations=DATA_FILE_PATHS)
