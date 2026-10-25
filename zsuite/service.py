"""Service container and base class for shared resources and configuration."""


class SVCObj:
    """Base class providing access to the global service container.

    Inherit from this class to enable access to shared services via the `svc` class
    attribute. The `svc` attribute is set by the SVC class during initialization.

    **Example:**

    .. code-block:: python

        class MyService(SVCObj):
            def do_work(self):
                config = self.svc.config
                db_name = config.get("database")


        svc = SVC(config={"database": "mydb"})
        service = MyService()
        service.do_work()  # Can access svc.config
    """

    svc = None


class SVC:
    """Service container for application-wide shared resources and configuration.

    Central service object that registers itself globally with SVCObj to provide shared
    resources (like configuration) to child objects throughout the application.

    **Example:**

    .. code-block:: python

        svc = SVC(config=my_config)
        config = SVCObj().svc.config
    """

    def __init__(self, config=None, unittesting=False, **kwargs):
        """Initialize the service container and register it globally.

        Sets this instance as the global service object accessible via SVCObj.svc.
        All SVCObj instances will reference this shared service container.

        :param config: Configuration dict, consulted by config_var() after environment variables.
        :param unittesting: Flag to indicate unit testing mode.
        :param kwargs: Additional keyword arguments, set as attributes on the instance.
        """
        SVCObj.svc = self
        self.config = config
        self._unittesting = unittesting
        for key, value in kwargs.items():
            setattr(self, key, value)
