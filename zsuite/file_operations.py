import logging
import os

from .config import config_var


def remove_if_exists(fpath: str):
    """
    Given a full path to a file, remove it if it exists.
    Returns none regardless of file's presence

    :param fpath: full path to file
    :return: None
    """
    try:
        os.remove(fpath)
        return True
    except OSError:
        return False


def debug_file_path(fpath: str, force_print: bool = False):
    # Determine if debugging should be enabled for logging
    should_debug = config_var("DEBUG_FILE_PATH", False) or config_var("LOG_LEVEL", "INFO") == "DEBUG"

    # Collect debug information
    debug_info = []
    summary_dict = {}

    debug_info.append(f"\n---------------------------\nFILE DEBUG for: {fpath}")
    summary_dict["file_path"] = fpath

    is_absolute = os.path.isabs(fpath)
    debug_info.append(f"Path is absolute: {'Yes' if is_absolute else 'No'}")
    summary_dict["is_absolute"] = is_absolute

    absolute_path = os.path.abspath(fpath)
    debug_info.append(f"Absolute path: {absolute_path}")
    summary_dict["absolute_path"] = absolute_path

    file_exists = os.path.isfile(fpath)
    debug_info.append(f"File exists: {'Yes' if file_exists else 'No'}")
    summary_dict["file_exists"] = file_exists

    file_readable = os.access(fpath, os.R_OK)
    debug_info.append(f"File is readable: {'Yes' if file_readable else 'No'}")
    summary_dict["file_readable"] = file_readable

    file_writable = os.access(fpath, os.W_OK)
    debug_info.append(f"File is writable: {'Yes' if file_writable else 'No'}")
    summary_dict["file_writable"] = file_writable

    file_executable = os.access(fpath, os.X_OK)
    debug_info.append(f"File is executable: {'Yes' if file_executable else 'No'}")
    summary_dict["file_executable"] = file_executable

    file_is_directory = os.path.isdir(fpath)
    debug_info.append(f"File is a directory: {'Yes' if file_is_directory else 'No'}")
    summary_dict["file_is_directory"] = file_is_directory

    parent_dir = os.path.dirname(absolute_path)
    parent_dir_exists = os.path.isdir(parent_dir)
    debug_info.append(f"Parent directory exists: {'Yes' if parent_dir_exists else 'No'}")
    summary_dict["parent_dir_exists"] = parent_dir_exists

    parent_dir_writable = os.access(parent_dir, os.W_OK)
    debug_info.append(f"Parent directory is writable: {'Yes' if parent_dir_writable else 'No'}")
    summary_dict["parent_dir_writable"] = parent_dir_writable

    parent_dir_readable = os.access(parent_dir, os.R_OK)
    debug_info.append(f"Parent directory is readable: {'Yes' if parent_dir_readable else 'No'}")
    summary_dict["parent_dir_readable"] = parent_dir_readable

    # Combine all debug messages into a multi-line string
    combined_debug_message = "\n".join(debug_info)
    combined_debug_message += "\n---------------------------\n"

    # Log at the appropriate level based on configuration, if should_debug is True
    if should_debug:
        log_level = config_var("LOG_LEVEL", "INFO")
        getattr(logging, log_level.lower())(f"{combined_debug_message}")

    if force_print:
        print(combined_debug_message)

    return summary_dict
