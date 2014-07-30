from MockConnection import MockConnection
import pickle


class ClientServerConnection:
    """Connects the server and client MockConnection

    This has manly been writen for testing and will not be used in production.
    """

    def __init__(self):
        self.client_conn = MockConnection()
        self.__register_handler(self.client_conn)
        self.server_conn = MockConnection()
        self.__register_handler(self.server_conn)
        self.print_data = False

    def __register_handler(self, conn):
        conn.set_send_handler(self.__send_handler)
        conn.set_close_handler(self.__close_handler)

    def __get_other_conn(self, conn):
        if conn is self.server_conn:
            return self.client_conn
        return self.server_conn

    def __get_connection_name(self, conn):
        if conn is self.server_conn:
            return 'Server'
        else:
            return 'Client'

    def __close_handler(self, conn):
        self.__get_other_conn(conn).close()

    def __send_handler(self, conn, data):
        if self.print_data:
            unpickle_data = None
            try:
                unpickle_data = pickle.loads(data)
            except:
                pass
            print ''
            print '%s -> %s: %s' % (self.__get_connection_name(conn),
                                    self.__get_connection_name(
                                        self.__get_other_conn(conn)),
                                    unpickle_data)
        self.__get_other_conn(conn).receive(data)
