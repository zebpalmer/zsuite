"""MongoDB client and database connection utilities.

All connection options are driven by config vars (environment or service config)
rather than code-level arguments -- deployment config is the single steering wheel.
For pymongo options outside the supported vocabulary, construct a MongoClient
yourself and pass it to get_mongo_db(client=...).
"""

import logging

from pymongo import MongoClient
from pymongo.database import Database

from .config import config_bool, config_var

__all__ = ["get_mongo", "get_mongo_client", "get_mongo_db"]

# Optional string config vars mapped to their MongoClient argument names.
_OPTIONAL_STR_OPTIONS = (
    ("MONGO_USERNAME", "username"),
    ("MONGO_PASSWORD", "password"),
    ("MONGO_REPLICASET", "replicaSet"),
    ("MONGO_AUTHSOURCE", "authSource"),
    ("MONGO_READPREFERENCE", "readPreference"),
)

# Optional boolean config vars mapped to (MongoClient argument, default).
# A None default means the option is omitted entirely when unset, deferring
# to pymongo's own default.
_OPTIONAL_BOOL_OPTIONS = (
    ("MONGO_TLS", "tls", None),
    ("MONGO_TLS_INSECURE", "tlsInsecure", None),
    ("MONGO_TZ_AWARE", "tz_aware", True),  # house convention: no naive datetimes
)


def get_mongo(init_db=None) -> tuple[MongoClient, Database]:
    """Get a MongoDB client and database connection in a single call.

    The for-humans entry point: most services need both the client (for connection
    management) and the database (for operations). All connection options come from
    config vars -- see :func:`get_mongo_client` for the full vocabulary.

    :param init_db: Optional callback function to execute after the database connection
                    is established. Receives the Database instance as its argument.
                    Useful for creating indexes or performing other initialization.
    :type init_db: callable | None
    :returns: Tuple of (MongoClient instance, Database instance).
    :rtype: tuple[MongoClient, Database]
    :raises ConfigurationError: If MONGO_HOST or MONGO_DB_NAME is not set.

    **Example:**

    .. code-block:: python

        def initialize_db(db):
            db.users.create_index("email")


        client, db = get_mongo(init_db=initialize_db)
    """
    client = get_mongo_client()
    db = get_mongo_db(init_db=init_db, client=client)
    return client, db


def get_mongo_client() -> MongoClient:
    """Create and return a MongoDB client configured entirely from config vars.

    There are no code-level options: every setting comes from the environment or
    service config, so deployment configuration is the single source of truth.
    For pymongo options outside this vocabulary, construct a MongoClient yourself
    and pass it to get_mongo_db(client=...).

    **Config vocabulary:**

    ==================== ================ ==========================================
    Config var           MongoClient arg  Behavior when unset
    ==================== ================ ==========================================
    MONGO_HOST           host             required -- raises ConfigurationError
    MONGO_USERNAME       username         omitted (unauthenticated connection)
    MONGO_PASSWORD       password         omitted
    MONGO_REPLICASET     replicaSet       omitted
    MONGO_AUTHSOURCE     authSource       omitted
    MONGO_READPREFERENCE readPreference   omitted
    MONGO_TLS            tls              omitted (pymongo default)
    MONGO_TLS_INSECURE   tlsInsecure      omitted (pymongo default)
    MONGO_TZ_AWARE       tz_aware         defaults to True (aware datetimes)
    ==================== ================ ==========================================

    Boolean vars accept only 'true'/'false' (see config_bool).

    :returns: Configured MongoClient instance.
    :rtype: MongoClient
    :raises ConfigurationError: If MONGO_HOST is not set, or a boolean config var
                                holds a non-boolean value.
    """
    options = {"host": config_var("MONGO_HOST")}

    for cfg_name, arg_name in _OPTIONAL_STR_OPTIONS:
        value = config_var(cfg_name, None)
        if value is not None:
            options[arg_name] = value

    for cfg_name, arg_name, default in _OPTIONAL_BOOL_OPTIONS:
        value = config_bool(cfg_name, default)
        if value is not None:
            options[arg_name] = value

    return MongoClient(**options)


def get_mongo_db(init_db=None, client: MongoClient = None) -> Database:
    """Get a MongoDB database connection.

    Returns a database connection using the database name specified in MONGO_DB_NAME
    configuration. If a client is not provided, one is created via get_mongo_client().
    Passing your own client is the escape hatch for pymongo options that the config
    vocabulary does not cover.

    :param init_db: Optional callback function to execute after the database connection
                    is established. Receives the Database instance as its argument.
    :type init_db: callable | None
    :param client: Existing MongoClient instance to use. If None, creates a new client
                   using get_mongo_client().
    :type client: MongoClient | None
    :returns: Database instance for the configured database.
    :rtype: Database
    :raises ConfigurationError: If MONGO_DB_NAME configuration variable not set.
    """
    if client is None:
        client = get_mongo_client()
    db_name = config_var("MONGO_DB_NAME")
    db = getattr(client, db_name)
    if init_db is not None:
        logging.info("Running database initialization function")
        init_db(db)
    return db
