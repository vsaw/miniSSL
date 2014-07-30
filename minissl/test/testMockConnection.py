import unittest
from minissl.test.MockConnection import MockConnection


class TestMockMockConnection(unittest.TestCase):
    def setUp(self):
        self.conn = MockConnection()
        self.conn.set_close_handler(self.close_handler)
        self.closed_conn = None
        self.was_close_handler_called = False
        self.conn.set_receive_handler(self.receive_handler)
        self.last_received_data = None
        self.receive_conn = None
        self.conn.set_send_handler(self.send_handler)
        self.last_sent_data = None

    def close_handler(self, conn):
        self.was_close_handler_called = True
        self.closed_conn = conn

    def receive_handler(self, conn, data):
        self.last_received_data = data
        self.receive_conn = conn

    def send_handler(self, conn, data):
        self.last_sent_data = data

    def test_close_handler_called(self):
        self.assertTrue(self.conn.is_open)
        self.conn.close()
        self.assertTrue(self.was_close_handler_called)
        self.assertEqual(self.conn, self.closed_conn)
        self.assertFalse(self.conn.is_open)

    def test_receive_handler_called(self):
        some_data = [1, 2, 3, 4]
        self.conn.receive(some_data)
        self.assertEqual(some_data, self.last_received_data)
        self.assertEqual(some_data, self.conn.last_received_data)
        self.assertEqual(self.conn, self.receive_conn)

    def test_sent_data_store(self):
        some_data = [1, 2, 3, 4]
        self.conn.send(some_data)
        self.assertEqual(some_data, self.conn.last_sent_data)

    def test_send_handler_called(self):
        some_data = [1, 2, 3, 4]
        self.conn.send(some_data)
        self.assertEqual(some_data, self.last_sent_data)
