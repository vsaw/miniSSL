import minissl.keyutils as keyutils
import pickle
import minissl.Utils as Utils
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA


class SslClient:
    """A SSL Client to talk to our SSL Server

    This client does all the crypto stuff to establish a channel. Once the keys
    have been established it will notify the top level user that the secure
    chanel is ready with the connected_handler.
        Sending data is easily accessible through the send method. Received data
    will be delivered with the received_handler.
    """

    def __init__(self, conn, ca, cert=None, private_key=None):
        """Initialize the SslClient and connect to the endpoint of conn

        :param conn:
            A connection to connect to a SslServer
        :param ca:
            The certificate authority to use
        :param cert:
            The optional client certificate
        :param private_key:
            The optional private key of the client

        If the cert or private key are not supplied the client is not able to
        connect to server that require client authentication.
        """
        # generate the init nonce
        self.client_nonce = keyutils.generate_nonce()
        # the nonce that has been received by the server
        self.server_nonce = None
        # the negotiated crypto algorithm
        self.crypto = None
        # the certificate that was received from the server
        self.server_cert = None
        # True if the server requests client authentication
        self.client_auth = False
        # The client certificate
        self.cert = cert
        # The certificate authority to use
        self.ca = ca
        # the private key of the client
        self.private_key = private_key
        # todo check that the private key is valid and can sign stuff
        # Remembers the step the client is currently in
        self.step = 'ClientInit'
        # the established key for the encryption
        self.k1 = None
        # the established key to sign the HMAC
        self.k2 = None
        # the encrypted pre-master key
        self.p_encrypted = None
        # the mc as exchanged in some messages
        self.mc = None
        # Store the connection to reach the server and register the receive
        # handler
        self.conn = conn
        self.conn.set_receive_handler(self.__conn_receive_handler)
        # the handler to call when a secure connection has been established
        self.connected_handler = None
        # buffer the last received application data in plain text to send it
        # to the user of this class if the session was establised before they
        # subscribe to the receive_handler
        self.buffered_plaintext = None
        # the handler to call when application data has been received
        # it can only be called when the secure chanel has already been
        # established
        self.receive_handler = None
        # Send the ClientInit message
        # todo refactor to external function
        self.conn.send(pickle.dumps(
            ['ClientInit', self.client_nonce, 'AES-CBC-128-HMAC-SHA1']))

    def __notify_upstream_receiver(self, serialized_data):
        """Notify the user of this class about new application data

        :param serialized_data:
            The serialized and still encrypted data from the connection

        This will uncrypt the message and forward it to the handler, so that the
        handler can completely focus on the application.
        """
        try:
            data = pickle.loads(serialized_data)
        except:
            return
        plaintext = Utils.aes_128_hmac_decrypt_verify(data[0], data[2],
                                                      Utils.extract_aes_key(
                                                          self.k1), data[1],
                                                      self.k2)
        if plaintext is not None:
            self.buffered_plaintext = plaintext
        if self.receive_handler is not None:
            self.receive_handler(self, plaintext)

    def __conn_receive_handler(self, conn, data):
        """Handler that will be called when the underlying connection sent data

        :param conn:
            the connection that sent the data
        :param data:
            the serialized raw data
        """
        if self.step == 'ClientInit':
            if self.__parse_server_init(data):
                self.step = 'ClientKex'
                self.__send_client_kex()
                return
        elif self.step == 'ClientKex':
            if self.__parse_server_kex_ack(data):
                self.step = 'Connect'
                if self.connected_handler is not None:
                    self.connected_handler(self)
                return
        elif self.step == 'Connect':
            self.__notify_upstream_receiver(data)
            #if self.receive_handler is not None:
            #    self.receive_handler(self, data)
            return
        self.conn.close()
        self.step = 'Disconnect'

    def __parse_server_kex_ack(self, data):
        """Parses the key acknowledge message from the server

        :param data:
            the serialized message
        :return:
            True if the response was valid, False otherwise
        """
        try:
            ack = pickle.loads(data)
            ms_raw = 'ClientKex' + self.p_encrypted + self.mc
            if self.client_auth:
                ms_raw += self.cert
            return ack == keyutils.create_hmac(self.k2, ms_raw)
        except:
            pass
        return False

    def __send_client_kex(self):
        """Send the key exchange message to the sever"""
        p = keyutils.generate_random(46)
        cipher_rsa = PKCS1_OAEP.new(
            keyutils.read_pubkey_from_pem(self.server_cert))
        self.p_encrypted = cipher_rsa.encrypt(p)
        self.k1 = Utils.compute_k1(p, self.client_nonce, self.server_nonce)
        self.k2 = Utils.compute_k2(p, self.client_nonce, self.server_nonce)
        self.mc = Utils.compute_mc(self.k2, self.client_nonce,
                                   self.server_nonce, self.server_cert,
                                   self.client_auth)
        kex_msg = ['ClientKex', self.p_encrypted, self.mc]
        if self.client_auth:
            # This is where the signature of the client as added.
            #
            # Here the implementation differs a bit from the standard as defined
            # in RFC 4346 (https://tools.ietf.org/html/rfc4346).
            #
            # First of all the Certificate verify message as defined in Section
            # 7.4.8 (https://tools.ietf.org/html/rfc4346#section-7.4.8) is not
            # implemented as specified. Even though RSA is used as a signature
            # algorithm the exchanged signature does not contain the MD5 hash,
            # only the SHA hash is computed and transmitted.
            #
            # Second of all this implementation uses RSASSA-PSS as specified in
            # RFC 3447 Section 8.1
            # (https://tools.ietf.org/html/rfc3447#section-8.1) even though it
            # is not mentioned in RFC 4346. However RFC 3447 Section 8
            # (https://tools.ietf.org/html/rfc3447#section-8) states that:
            #
            #       Although no attacks are known against RSASSA-PKCS1-v1_5, in
            #       the interest of increased robustness, RSASSA-PSS is
            #       recommended for eventual adoption in new applications.
            #
            # Therefore RSASSA-PSS is used in favor of the RSASSA-PKCS1-v1_5. In
            # my opinion this design choice is still within the granted degrees
            # of freedom how RSA is performed.
            h = SHA.new()
            h.update(self.server_nonce + self.p_encrypted)
            signer = PKCS1_PSS.new(
                keyutils.read_privkey_from_pem(self.private_key))
            kex_msg += [self.cert, signer.sign(h)]
        self.conn.send(pickle.dumps(kex_msg))

    def __parse_server_init(self, data):
        """Parses a ServerInit message

        :param data:
            The serialzed message

        :return:
            True if the message could be parse and was valid, False otherwise
        """
        try:
            server_init = pickle.loads(data)
            is_right_length = len(server_init) == 4 or len(server_init) == 5
            is_server_init = server_init[0] == 'ServerInit'
            is_valid_nonce = Utils.is_valid_nonce(server_init[1])
            is_supported_crypto = server_init[2] == 'AES-CBC-128-HMAC-SHA1'
            is_valid_cert = Utils.is_valid_certificate(server_init[3], self.ca,
                                                       self.conn.common_name)
            if is_right_length and is_server_init and is_valid_nonce and \
                    is_supported_crypto and is_valid_cert:
                if len(server_init) == 5:
                    if server_init[4] == 'CertReq' and self.cert is not None:
                        self.client_auth = True
                    else:
                        return False
                self.server_nonce = server_init[1]
                self.crypto = server_init[2]
                self.server_cert = server_init[3]
                return True
        except:
            return False

    def close(self):
        """Terminate the SSL connection

        This will put the client in the disconnect and close the underlying
        connection.
        """
        self.step = 'Disconnect'
        self.conn.set_receive_handler(None)
        self.conn.set_close_handler(None)
        self.conn.close()

    def set_connected_handler(self, handler):
        """Subscribe a handler that will be called when the connection is
        established

        :param handler:
            The handler to call

        The handler will be called the following way:

            handler(self)

        so that the handler can determine the SslClient if he is in charge of
        more than one.
        """
        self.connected_handler = handler
        if handler is not None and self.step == 'Connect':
            handler(self)

    def set_receive_handler(self, handler):
        """Subscribe a handler that will be called when application data has been
        received

        :param handler:
            The handler to call

        The handler will be called the following way:

            handler(self, plaintext)

        so that the handler can determine the SslClient if he is in charge of
        more than one.
        """
        self.receive_handler = handler
        if self.buffered_plaintext is not None and handler is not None:
            handler(self, self.buffered_plaintext)

    def send(self, plaintext):
        """Securely send plaintext

        :param plaintext:
            The plaintext to send
        """
        if self.step == 'Connect':
            ciphertext, iv, hmac = Utils.aes_128_hmac_encrypt(plaintext,
                                                              Utils.extract_aes_key(
                                                                  self.k1),
                                                              self.k2)
            serialized_data = pickle.dumps([ciphertext, iv, hmac])
            self.conn.send(serialized_data)
