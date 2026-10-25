"""MongoDB query sanitation to prevent NoSQL injection attacks."""

from flask import abort

from ..exceptions import MongoQueryError

__all__ = ["VALID_MONGO_OPERATORS", "sanitize_mongo_query", "validate_mongo_query"]

# define a set of valid mongo operators for query input sanitation
VALID_MONGO_OPERATORS = {
    "$eq",
    "$gt",
    "$gte",
    "$lt",
    "$lte",
    "$ne",
    "$in",
    "$nin",
    "$exists",
    "$regex",
}


def validate_mongo_query(data):
    """Recursively validate a MongoDB query structure, raising on unsafe input.

    Pure validation core with no Flask dependency -- safe to call from daemons,
    workers, and unit tests. Walks through the query structure (dicts, lists, and
    strings) and rejects:

    - **Keys** containing ``$`` that are not in VALID_MONGO_OPERATORS (operator
      injection, e.g. ``$where``).
    - **String values** starting with ``$`` (field-reference injection risk in
      aggregation contexts, e.g. a crafted ``"$password"``). A ``$`` elsewhere in
      a value (prices, free text) is allowed -- string values are inert in find()
      equality matches.

    :param data: MongoDB query structure to validate. Can be dict, list, or any value.
    :type data: dict | list | str | any
    :raises MongoQueryError: If an unauthorized operator key or a ``$``-prefixed
                             string value is found.

    **Valid Operators:**

    - Comparison: $eq, $gt, $gte, $lt, $lte, $ne
    - Logical: $in, $nin
    - Element: $exists
    - Evaluation: $regex

    .. note::
        Dangerous operators like $where, $function, $accumulator, and others that
        allow code execution are explicitly blocked by not being in the allowed list.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if "$" in key and key not in VALID_MONGO_OPERATORS:
                raise MongoQueryError(f"Invalid query parameter key: {key}")
            validate_mongo_query(value)
    elif isinstance(data, list):
        for item in data:
            validate_mongo_query(item)
    elif isinstance(data, str) and data.startswith("$"):
        raise MongoQueryError(f"Invalid query parameter value: {data!r} ('$'-prefixed values are not allowed)")


def sanitize_mongo_query(data):
    """Validate a MongoDB query within a Flask request, aborting with 400 on unsafe input.

    Thin Flask wrapper around :func:`validate_mongo_query` for use in views handling
    user-supplied query parameters. See validate_mongo_query for the validation rules.

    :param data: MongoDB query structure to validate. Can be dict, list, or any value.
    :type data: dict | list | str | any
    :raises HTTPException: 400 Bad Request if validation fails.

    **Example:**

    .. code-block:: python

        # Valid queries
        sanitize_mongo_query({"age": {"$gt": 18}})
        sanitize_mongo_query({"status": {"$in": ["active", "pending"]}})
        sanitize_mongo_query({"note": "costs $5"})  # interior '$' in values is fine

        # Invalid queries - will abort with 400
        sanitize_mongo_query({"$where": "this.age > 18"})  # Unauthorized operator
        sanitize_mongo_query({"name": "$admin"})  # '$'-prefixed string value
        sanitize_mongo_query({"$ne": {"password": None}})  # '$' in key position

    .. warning::
        This function calls Flask's abort() on validation failure. Outside a Flask
        request context, use :func:`validate_mongo_query` and catch MongoQueryError.
    """
    try:
        validate_mongo_query(data)
    except MongoQueryError as e:
        abort(400, description=str(e))
