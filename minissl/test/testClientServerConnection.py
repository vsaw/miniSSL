import unittest
from ClientServerConnection import ClientServerConnection
from minissl.SslClient import SslClient
from minissl.SslServer import SslServer
import PemSamples


class TestClientServerConnection(unittest.TestCase):
    def setUp(self):
        self.conn = ClientServerConnection()

    def test_client_to_server(self):
        data = 'some string'
        self.conn.client_conn.send(data)
        self.assertEqual(data, self.conn.server_conn.last_received_data)

    def test_server_to_client(self):
        data = 'some other string'
        self.conn.server_conn.send(data)
        self.assertEqual(data, self.conn.client_conn.last_received_data)

    def test_mutual_close(self):
        self.conn.client_conn.close()
        self.assertFalse(self.conn.server_conn.is_open)

    def test_ssl_connection_establish(self):
        self.conn.print_data = False
        # create a sever instance
        server = SslServer(PemSamples.minnissl_server_pem,
                           PemSamples.minnissl_server_key_pem,
                           PemSamples.minnissl_ca_pem)
        # create a client instance with a connection to the server
        client = SslClient(self.conn.client_conn, PemSamples.minnissl_ca_pem)
        # call the on_client_connect method of the server
        server.on_client_connect(self.conn.server_conn,
                                 self.conn.server_conn.last_received_data)
        # check that both connection are open
        self.assertTrue(self.conn.client_conn.is_open)
        self.assertTrue(self.conn.server_conn.is_open)
        # the client should be in the connect state now
        self.assertEqual('Connect', client.step)

    def test_ssl_connection_establish_with_client_auth(self):
        self.conn.print_data = False
        # create a sever instance
        server = SslServer(PemSamples.minnissl_server_pem,
                           PemSamples.minnissl_server_key_pem,
                           PemSamples.minnissl_ca_pem, True)
        # create a client instance with a connection to the server
        client = SslClient(self.conn.client_conn, PemSamples.minnissl_ca_pem,
                           PemSamples.minnissl_client_pem,
                           PemSamples.minnissl_client_key_pem)
        # call the on_client_connect method of the server
        server.on_client_connect(self.conn.server_conn,
                                 self.conn.server_conn.last_received_data)
        # check that both connection are open
        self.assertTrue(self.conn.client_conn.is_open)
        self.assertTrue(self.conn.server_conn.is_open)
        # the client should be in the connect state now
        self.assertEqual('Connect', client.step)
