from minissl.AbstractConnection import AbstractConnection


class MockConnection(AbstractConnection):
    # todo document

    def __init__(self):
        AbstractConnection.__init__(self)
        self.is_open = True
        self.last_sent_data = None
        self.last_received_data = None
        self.send_handler = None

    def close(self):
        AbstractConnection.close(self)

    def receive(self, data):
        """Receive data using this MockConnection.

        :param data:
            The data that was received

        This helps to fake receiving data. This will invoke the receive handler.
        """
        self.last_received_data = data
        if not self._receive_handler is None:
            self._receive_handler(self, data)

    def send(self, data):
        self.last_sent_data = data
        AbstractConnection.send(self, data)
        if not self.send_handler is None:
            self.send_handler(self, data)

    def set_send_handler(self, handler):
        self.send_handler = handler
