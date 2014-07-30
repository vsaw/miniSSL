class AbstractConnection:
    """An abstract connection to send and receive data

    This is used to abstract the underlying communication stream from the
    implementation of the miniSSL protocol.
    """

    def __init__(self):
        self._close_handler = None
        self._receive_handler = None
        self.is_open = False
        # The expected common name of the endpoint
        #
        # This can be used for cryptographic verification if certificate of the
        # endpoint is transmitted.
        self.common_name = None

    def close(self):
        """Closes the connection and calls the close handler

        Calling close on a closed connection has no effect.
        """
        if self.is_open:
            self.is_open = False
            if not self._close_handler is None:
                self._close_handler(self)

    def send(self, data):
        """Send raw data to the endpoint of the connection

        :param data:
            An array of bytes
        """
        pass

    def set_close_handler(self, handler):
        """Sets a handler that will be called when the connection was closed

        :param handler:
            The handler to call

        The handler will be called as follows if either end closes the
        connection:

            handler(self)

        where self is a reference to the connection that was closed.
        """
        self._close_handler = handler

    def set_receive_handler(self, handler):
        """Sets a handler that will be called when data is received

        :param handler:
            The handler to be called.

        The handler will be invoked as follows:

            handler(self, data)

        where self is a reference to the connection and data is an array of
        bytes.

        Depending on the underlying implementation of the connection, the
        handler might be called by a separate thread. It is the duty of the
        handler to deal with it.
        """
        self._receive_handler = handler
