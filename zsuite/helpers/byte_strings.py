def want_bytes(s: str | bytes, encoding="utf-8", errors="strict") -> bytes:
    """
    Ensures that the given input is in bytes format.

    If the input is a string, it encodes it to bytes using the specified encoding and error handling strategy.
    If the input is already in bytes, it returns it unchanged.

    :param s: The input value, which can be either a string or bytes.
    :param encoding: Optional; the encoding to use when converting a string to bytes. Default is "utf-8".
    :param errors: Optional; the error handling strategy to use when converting a string to bytes. Default is "strict".
    :return: The input value in bytes format.
    """
    if isinstance(s, str):
        s = s.encode(encoding, errors)
    return s
