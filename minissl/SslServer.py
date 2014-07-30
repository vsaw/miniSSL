import minissl.keyutils as keyutils
import pickle
import minissl.Utils as Utils
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_PSS


class ConnectedSslClient:
    """Stores the states and keys of connected clients

    The server has a list of them to remember the established session
    information for each client.
    """

    def __init__(self, conn, client_nonce, crypto):
        """Store the state of a currently connected SslClient

        :param conn:
            The connection to reach the client
        :param client_nonce:
            The nonce sent by the client
        :param crypto:
            The crypto suite and protocols to use

        Right now crypto is just the string describing the used algorithms. At
        some point it could make sense to have it as a generic interface that
        implements functions like 'encrypt' and 'sign' but this is only gonna
        happen if I have time for it :-)
        """
        # The client certificate
        self.cert = None
        # The nonce that was received from the client
        self.client_nonce = client_nonce
        # The connection to reach the client
        self.conn = conn
        # The selected crypto algorithms to communicate with the client
        self.crypto = crypto
        # The established encryption key
        self.k1 = None
        # The established signing key
        self.k2 = None
        # The mc field received by the client
        self.mc = None
        # The encrypted pre-master secret received by the client
        self.p_encrypted = None
        # The server nonce that was sent to the client
        self.server_nonce = None
        # The step that the SSL establish is at
        #
        # The steps can be:
        # 1. Disconnect
        # 2. ClientInit
        # 3. ServerInit
        # 4. ClientKex
        # 5. ServerKexAck
        # 6. Connect
        self.step = 'ClientInit'


class SslServer:
    """The SSL Server that terminates miniSSl endpoints for the clients

    To hide the actual communication method from the flow this server works with
    AbstractConnection objects.

    To start a key establishment sequence with a client the on_client_connect
    method of the server should be called when the first data from the client
    was received. The server will then start parsing the data and establishing
    a key with the client.
    """

    def __init__(self, servercert, serverprivkey, ca, client_auth=False):
        """Starts the SSL server

        :param servercert:
            The certificate of the server issued by the ca as PEM
        :param serverprivkey:
            The private key of the server as PEM
        :param ca:
            The certificate authority that signed the servercert as PEM
        :param client_auth:
            Require client authentication

        :raise Exception:
            If the parameters failed validation
        """
        # check the arguments before processing
        if servercert is None or serverprivkey is None or ca is None:
            raise Exception

        # ensure that the cert is from the given ca and that both certificates
        # have not expired
        if not keyutils.verify_certificate(ca, servercert):
            raise Exception('servercert not signed by ca')

        # check if the private key is valid and can be parsed
        if not keyutils.read_privkey_from_pem(serverprivkey).has_private():
            raise Exception('serverprivkey must contain a private key')

        # the servercert must not have a private key
        if keyutils.read_pubkey_from_pem(servercert).has_private():
            raise Exception('servercert must not contain a private key')

        # The trusted certificate authority to validate any certificate against
        # as PEM
        self.ca = ca
        # The certificate issued to the server by the CA as PEM
        self.cert = servercert
        # True if client authentication it required, false otherwise
        self.client_auth = client_auth
        # Store all the currently connected clients here
        self.connected_clients = []
        # The handler that will be called when a new client has successfully
        # established a SSL connection with the server
        self.connection_established_handler = None
        # The handler will be called whenever a client message has been received
        self.client_message_handler = None
        # The private key of the server as PEM
        self.private_key = serverprivkey

    def __client_disconnect_handler(self, conn):
        """Remove the client from our list of connected clients when a
        connection closes

        :param conn:
            The connection that has been closed
        """
        client = self.__find_connected_client_for_connection(conn)
        if client is not None:
            self.__disconnect_client(client)

    def __disconnect_client(self, client):
        """Disconnect a client and remove his session

        :param client:
            The client to disconnect
        """
        self.connected_clients.remove(client)
        client.conn.close()

    def __find_connected_client_for_connection(self, conn):
        """Find a connected client for given connection

        :param conn:
            The connection that sent data

        :return:
            A ConnectedSslClient or None if no client is associated with conn

        If by any chance more than one client are associated with a connection
        all of them will be disconnected to get the session handling back on
        track.
        """
        # Filter all the clients that have the given connection
        clients = filter(lambda x: x.conn == conn, self.connected_clients)
        # if only one client is found return it, if more clients are found
        # remove them because something got messed up with the session handling
        if len(clients) == 1:
            return clients[0]
        else:
            for client in clients:
                self.__disconnect_client(client)
        return None

    @staticmethod
    def __parse_client_init(data):
        """Parse raw data to see if it contains a ClientInit message

        :param data:
            The raw serialized data that was received

        :return:
            A tuple (nonce, crypto algorithms) used or (None, None) upon fail
        """
        try:
            init_data = pickle.loads(data)
            if len(init_data) == 3:
                is_client_init = init_data[0] == 'ClientInit'
                is_valid_nonce = Utils.is_valid_nonce(init_data[1])
                is_supported_crypto = init_data[2] == 'AES-CBC-128-HMAC-SHA1'
                if is_valid_nonce and is_client_init and is_supported_crypto:
                    return init_data[1], init_data[2]
        except:
            pass
        return None, None

    def __notify_on_connection_established(self, client):
        """Notify the connection established handler about a new connected
        client

        :param client:
            The new connected client
        """
        if self.connection_established_handler is not None:
            self.connection_established_handler(self, client.cert)

    def __parse_client_kex_message(self, client, data):
        """Parse the client key exchange message

        :param client:
            The client that sent the message
        :param data:
            The raw serialized date received

        :return:
            True if the message was valid and could be parsed, False otherwise
        """
        try:
            # deserialize the data
            kex_msg = pickle.loads(data)

            # check the length, to see if all required fields are there
            if self.client_auth:
                is_right_length = 5 == len(kex_msg)
            else:
                is_right_length = 3 == len(kex_msg)
            if not is_right_length:
                return False

            # right message type?
            if not kex_msg[0] == 'ClientKex':
                return False

            # decrypt p and check it
            cipher_rsa = PKCS1_OAEP.new(RSA.importKey(self.private_key))
            p = cipher_rsa.decrypt(kex_msg[1])
            if not Utils.is_valid_nonce(p, 46):
                return False

            # calculate and check the MAC
            k1 = Utils.compute_k1(p, client.client_nonce, client.server_nonce)
            k2 = Utils.compute_k2(p, client.client_nonce, client.server_nonce)
            if not kex_msg[2] == Utils.compute_mc(k2, client.client_nonce,
                                                  client.server_nonce,
                                                  self.cert, self.client_auth):
                return False

            if self.client_auth:
                # Check if the client certificate is from our trusted ca
                if not keyutils.verify_certificate(self.ca, kex_msg[3]):
                    return False

                # check if the message has the clients signature
                h = SHA.new()
                h.update(client.server_nonce + kex_msg[1])
                pub_key = keyutils.read_pubkey_from_pem(kex_msg[3])
                verifier = PKCS1_PSS.new(pub_key)
                if not verifier.verify(h, kex_msg[4]):
                    return False

            # All check have passed, add the received data to the session
            client.k1 = k1
            client.k2 = k2
            client.mc = kex_msg[2]
            client.p_encrypted = kex_msg[1]
            if self.client_auth:
                client.cert = kex_msg[3]
            return True
        except:
            pass
        return False

    def receive_handler(self, conn, data):
        """Internal receive handler that will be notified about incoming data

        :param conn:
            The connection that sent the data
        :param data:
            The received data

        The receive handler will depending on the status of the client
        associated with the connection call a handler that actually parses the
        message.

        This follows the set_receive_handler specification of the
        AbstractConnection.
        """
        # find if this connection is known in our connected ssl client list
        # if it is not close the connection and return
        client = self.__find_connected_client_for_connection(conn)
        if client is None:
            # conn.close()
            self.on_client_connect(conn, data)
            return

        # check the step of the client connect process and call the appropriate
        # handler
        if client.step == 'ServerInit':
            if self.__parse_client_kex_message(client, data):
                self.__send_sever_kex_ack_msg(client)
            else:
                self.__disconnect_client(client)
        elif client.step == 'ServerKexAck' or client.step == 'Connect':
            client.step == 'Connect'
            if not self.__notify_on_client_message_received(client, data):
                # the message could not be encrypted or failed HMAC
                self.__disconnect_client(client)

    def __notify_on_client_message_received(self, client, serialized_data):
        """Notify the handler about new received messages from a client

        :param client:
            The client that sent the message
        :param serialized_data:
            The serialized data that was received from the handler

        :return:
            True if the message was properly encrypted, False otherwise
        """
        if self.client_message_handler is not None:
            try:
                data = pickle.loads(serialized_data)
                # decrypt the data and pass it to the other guy
                plaintext = Utils.aes_128_hmac_decrypt_verify(data[0], data[2],
                                                              Utils.extract_aes_key(
                                                                  client.k1),
                                                              data[1],
                                                              client.k2)
                if plaintext is not None:
                    response = self.client_message_handler(self, client.cert,
                                                           plaintext)
                    if response is not None:
                        self.__send_encrypted_message(client, response)
            except:
                pass
            return False
        return True

    @staticmethod
    def __send_encrypted_message(client, msg):
        """Sends an encrypted message to a client

        :param client:
            The client ot send the message to
        :param msg:
            The plaintext message to encrypt and send
        """
        encrypted_msg, iv, mac = Utils.aes_128_hmac_encrypt(msg,
                                                            Utils.extract_aes_key(
                                                                client.k1),
                                                            client.k2)
        client.conn.send(pickle.dumps([encrypted_msg, iv, mac]))

    def __send_server_init(self, client):
        """Sends the ServerInit to the client

        :param client:
            The client to send the ServerInit to
        """
        client.server_nonce = keyutils.generate_nonce()
        data = ['ServerInit', client.server_nonce, 'AES-CBC-128-HMAC-SHA1',
                self.cert]
        if self.client_auth:
            data.append('CertReq')
        client.step = 'ServerInit'
        client.conn.send(pickle.dumps(data))

    def __send_sever_kex_ack_msg(self, client):
        """Send a key exchange acknowledge message to the client

        :param client:
            The client to send it to

        This message follows the 'ClientKex' message received from the client.
        """
        client.step = 'ServerKexAck'
        ms_raw = 'ClientKex' + client.p_encrypted + client.mc
        if self.client_auth:
            ms_raw += client.cert
        ms = keyutils.create_hmac(client.k2, ms_raw)
        client.conn.send(pickle.dumps(ms))
        self.__notify_on_connection_established(client)

    def on_client_connect(self, conn, data):
        """Handles new clients that want to establish a connection

        :param conn:
            The underlying AbstractConnection to the client
        :param data:
            Initial data sent by the client as raw bytes

        This method will terminate the connection if invoked by an already
        connected client.
        """
        # check if conn already has a session associated with it
        client = self.__find_connected_client_for_connection(conn)
        if client is not None:
            self.__disconnect_client(client)
            return

        (nonce, crypto) = self.__parse_client_init(data)
        if nonce is not None and crypto is not None:
            connected_client = ConnectedSslClient(conn, nonce, crypto)
            conn.set_receive_handler(self.receive_handler)
            conn.set_close_handler(self.__client_disconnect_handler)
            # Make sure the client is added to the list before the server sends
            # his ServerInit message otherwise it the rest of the communication
            # is synchronous the state will not be present.
            self.connected_clients.append(connected_client)
            self.__send_server_init(connected_client)
        else:
            conn.close()

    def set_connection_established_handler(self, handler):
        """Registers a handler that will be called when a new client has
        connected

        :param handler:
            The handler to call

        The handler will be called the following way:

            handler(self, client_certificate)

        If the client connected anonymously the client_certificate will be None
        self is a reference to this server.
        """
        self.connection_established_handler = handler

    def set_client_message_handler(self, handler):
        """Registers a handler that will be called when a client sends a message

        :param handler:
            The handler to call

        The handler will be called the following way:

            handler(self, client_certificate, message)

        If the client connected anonymously the client_certificate will be None
        self is a reference to this server.

        Any data that the handler returns will be send to the client.
        """
        self.client_message_handler = handler
