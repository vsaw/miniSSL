import socket
import asyncore
import pickle
from minissl.AbstractConnection import AbstractConnection


class PickleStreamWrapper(asyncore.dispatcher_with_send, AbstractConnection):
    """Buffers a stream until it contains valid data serialized by pickle.

    That is a big of an ugly glue code I had to come up with in the last minute.
    The SSL-Server and Client were developed by using custom AbstractConnection
    to hide the actual communication chanel.
        However the AbstractConnection does not do fragmentation, it is expected
    to always send and receive all data at once. After trying to implement a
    TCP based AbstractConnection type I noticed that all this underlying
    fragmentation and buffering of the IP breaks that pattern. Therefore this
    class has been written to glue the behavior of the AbstractConnection and
    the Networking sockets together.
    """

    def __init__(self, sock):
        """Creates a new PickleStream Wrapper for the underlying socket.

        :param sock:
            The underlying base socket
        """
        asyncore.dispatcher_with_send.__init__(self, sock)
        AbstractConnection.__init__(self)
        self.rx_buffer = ''
        self.tx_buffer = ''

    def handle_read(self):
        new_data = self.recv(1024)
        self.rx_buffer += new_data
        try:
            # try to load the buffer to see if we have something that pickle
            # understands. If it worked out send the data upstream, if not do
            # nothing and wait for the rest of the data to arrive
            unpickled_data = pickle.loads(self.rx_buffer)
            if self._receive_handler is not None:
                self._receive_handler(self, self.rx_buffer)
                # Clear the buffer
                self.rx_buffer = ''
        except:
            pass

    def handle_close(self):
        AbstractConnection.close(self)
        asyncore.dispatcher_with_send.close(self)

    def send(self, data):
        """Send all the data

        :param data:
            The data to send

        To match the AbstractConnection API this has to redirect send to sendall
        because send can not handle data that is larger than some 512 byte
        buffer limit. sendall on the other hand can without a problem.
        """
        self.socket.sendall(data)


class TcpDispatcher(asyncore.dispatcher):
    """A powerful TCP dispatcher based on asyncore to listen for incoming
    connections.

    See http://docs.python.org/2/library/asyncore.html for more information on
    the library.
    """

    def __init__(self, host, port, receive_callback):
        """Start a new dispatcher to listen on the given host socket

        :param host:
            The host interface to listen to
        :param port:
            The port to bind to
        :param receive_callback:
            This callback will be used to notify if an accepted TCP connection
            sent any data
        """
        asyncore.dispatcher.__init__(self)
        self.receive_callback = receive_callback
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accept(self):
        """Handle TCP accepts.

        In this case if it is a valid accept a separate handler will be launched
        that takes care of the rest of the messages being exchanged of the new
        accepted connection.
        """
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            print 'Incoming connection from %s' % repr(addr)
            wrapper = PickleStreamWrapper(sock)
            wrapper.set_receive_handler(self.receive_callback)
