from zsuite.exceptions import UndeterminedBool

FUZZY_TRUE = {"true", "t", "1", "yes", "y", "active", "enabled"}
FUZZY_FALSE = {"false", "f", "0", "no", "n", "inactive", "disabled"}


def fuzzy_bool(bs):
    """
    Given a value, try to determine if the value represents true or false.
    If a string is provided and the string is empty, return None.
    Any uncertain result will result in an exception.

    :param bs: test string
    :return: bool if bool can be determined, None if not
    """
    # TODO: Change this to a match/case statement and drop python3.9 support
    if bs is None:
        return None
    if isinstance(bs, bool):
        return bs
    elif isinstance(bs, int) and bs in [0, 1]:
        return bool(bs)
    elif isinstance(bs, str):
        bs = bs.lower()
        if bs in FUZZY_TRUE:
            return True
        elif bs in FUZZY_FALSE:
            return False
        if bs == "":
            return None
    raise UndeterminedBool(f"could not determine bool from value: {bs}")
