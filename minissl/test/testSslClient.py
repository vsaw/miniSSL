import unittest
from minissl.SslClient import SslClient
from MockConnection import MockConnection
import pickle
import minissl.keyutils as keyutils
import minissl.Utils as Utils
import PemSamples
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA


class TestSslClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_init_valid = ['ServerInit', keyutils.generate_nonce(),
                                 'AES-CBC-128-HMAC-SHA1',
                                 PemSamples.minnissl_server_pem]
        cls.server_init_valid_client_auth = ['ServerInit',
                                             keyutils.generate_nonce(),
                                             'AES-CBC-128-HMAC-SHA1',
                                             PemSamples.minnissl_server_pem,
                                             'CertReq']
        cls.server_init_rogue_cert = ['ServerInit', keyutils.generate_nonce(),
                                      'AES-CBC-128-HMAC-SHA1',
                                      PemSamples.rogue_ca_pem]

    def start_client(self, cert):
        # todo document
        self.conn = MockConnection()
        self.conn.set_close_handler(self.close_handler)
        self.closed_conn = None
        self.was_close_handler_called = False
        self.conn.set_receive_handler(self.receive_handler)
        self.last_received_data = None
        self.receive_conn = None
        self.conn.common_name = 'minissl-SERVER'
        # initialize the client
        self.client = SslClient(self.conn, PemSamples.minnissl_ca_pem, cert,
                                PemSamples.minnissl_client_key_pem)
        self.client.set_connected_handler(self.connected_handler)

    def setUp(self):
        self.start_client(None)
        self.connected_handler_was_called = False

    def tearDown(self):
        self.client.close()

    def close_handler(self, conn):
        self.was_close_handler_called = True
        self.closed_conn = conn

    def receive_handler(self, conn, data):
        self.last_received_data = data
        self.receive_conn = conn

    def connected_handler(self, source):
        self.connected_handler_was_called = True

    def test_client_init(self):
        rx_data = pickle.loads(self.conn.last_sent_data)
        self.assertEqual(3, len(rx_data))
        self.assertEqual('ClientInit', rx_data[0])
        self.assertTrue(Utils.is_valid_nonce(rx_data[1]))
        self.assertEqual('AES-CBC-128-HMAC-SHA1', rx_data[2])

    def test_invalid_server_cert(self):
        self.conn.receive(pickle.dumps(self.server_init_rogue_cert))
        self.assertEqual('Disconnect', self.client.step)
        self.assertFalse(self.conn.is_open)

    def test_can_not_handle_client_auth(self):
        self.conn.receive(pickle.dumps(self.server_init_valid_client_auth))
        self.assertEqual('Disconnect', self.client.step)
        self.assertFalse(self.conn.is_open)

    def test_valid_server_init_progress_to_client_kex(self):
        self.conn.receive(pickle.dumps(self.server_init_valid))
        self.assertEqual('ClientKex', self.client.step)
        self.assertTrue(self.conn.is_open)

    def test_valid_server_init_progress_to_client_kex_with_client_auth(self):
        self.start_client(PemSamples.minnissl_client_pem)
        self.conn.receive(pickle.dumps(self.server_init_valid_client_auth))
        self.assertEqual('ClientKex', self.client.step)
        self.assertTrue(self.conn.is_open)

    def test_unexpected_common_name(self):
        self.conn.common_name = 'maxissl-SERVER'
        self.conn.receive(pickle.dumps(self.server_init_valid))
        self.assertEqual('Disconnect', self.client.step)
        self.assertFalse(self.conn.is_open)

    def validate_client_kex_message(self, message, with_client_auth):
        # now obtain the client message and analyze it
        kex_msg = pickle.loads(message)
        if with_client_auth:
            self.assertEqual(5, len(kex_msg))
        else:
            self.assertEqual(3, len(kex_msg))
        self.assertEqual('ClientKex', kex_msg[0])
        # decrypt p
        cipher_rsa = PKCS1_OAEP.new(
            RSA.importKey(PemSamples.minnissl_server_key_pem))
        p = cipher_rsa.decrypt(kex_msg[1])
        # ensure that p is a 46 byte random value
        self.assertTrue(Utils.is_valid_nonce(p, 46))
        # generate and compare k1
        k1 = Utils.compute_k1(p, self.client.client_nonce,
                              self.client.server_nonce)
        self.assertEqual(k1, self.client.k1)
        # generate and compare k2
        k2 = Utils.compute_k2(p, self.client.client_nonce,
                              self.client.server_nonce)
        self.assertEqual(k2, self.client.k2)
        # calculate and compare m_c
        mc = Utils.compute_mc(k2, self.client.client_nonce,
                              self.client.server_nonce, self.client.server_cert,
                              with_client_auth)
        self.assertEqual(mc, kex_msg[2])
        if with_client_auth:
            # Check for the expected client certificate
            self.assertEqual(PemSamples.minnissl_client_pem, kex_msg[3])
            pub_key = keyutils.read_pubkey_from_pem(kex_msg[3])
            # make sure the client does not reveal any secrets
            self.assertFalse(pub_key.has_private())

            # Check the signature of the client
            h = SHA.new()
            h.update(self.client.server_nonce + kex_msg[1])
            verifier = PKCS1_PSS.new(pub_key)
            self.assertTrue(verifier.verify(h, kex_msg[4]))

    def test_valid_client_kex(self):
        # Call the test first to send a valid ServerInit message to the client
        self.test_valid_server_init_progress_to_client_kex()
        self.validate_client_kex_message(self.conn.last_sent_data, False)

    def test_valid_client_kex_with_client_auth(self):
        # Call the test first to send a valid ServerInit message to the client
        self.test_valid_server_init_progress_to_client_kex_with_client_auth()
        self.validate_client_kex_message(self.conn.last_sent_data, True)

    @unittest.skip("")
    def test_close_after_client_init(self):
        # todo implement
        self.fail()

    @unittest.skip("")
    def test_close_after_server_init(self):
        # todo implement
        self.fail()

    @unittest.skip("")
    def test_close_after_conn_established(self):
        # todo implement
        self.fail()

    def __generate_ms(self, client_auth):
        # todo document
        kex = pickle.loads(self.conn.last_sent_data)
        ms_raw = 'ClientKex' + kex[1] + kex[2]
        if client_auth:
            ms_raw += self.client.cert
        return keyutils.create_hmac(self.client.k2, ms_raw)

    def test_server_kex_ack_valid(self):
        self.test_valid_client_kex()
        ms = self.__generate_ms(False)
        self.conn.receive(pickle.dumps(ms))
        self.assertEqual('Connect', self.client.step)

    def test_server_kex_ack_valid_with_client_auth(self):
        self.test_valid_client_kex_with_client_auth()
        ms = self.__generate_ms(True)
        self.conn.receive(pickle.dumps(ms))
        self.assertEqual('Connect', self.client.step)

    def test_server_kex_ack_invalid(self):
        self.test_valid_client_kex_with_client_auth()
        ms = self.__generate_ms(False)
        self.conn.receive(pickle.dumps(ms))
        self.assertEqual('Disconnect', self.client.step)
        self.assertFalse(self.conn.is_open)

    def test_on_client_connected_notify(self):
        self.test_server_kex_ack_valid_with_client_auth()
        self.assertTrue(self.connected_handler_was_called)
