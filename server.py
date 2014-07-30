

import argparse
from minissl.SslServer import SslServer
from minissl.TcpDispatcher import TcpDispatcher
from minissl.test.PemSamples import minnissl_ca_pem
import asyncore

# Parse the command line according to the format of the assignment using the
# fabulous argparse
#
# Format:
#   ./server.py listen_port servercert serverprivkey {SimpleAuth, ClientAuth}
#       payload.txt
parser = argparse.ArgumentParser()
parser.add_argument('listenport', type=int)
parser.add_argument('servercert', type=argparse.FileType('r'))
parser.add_argument('serverprivkey', type=argparse.FileType('r'))
parser.add_argument('auth', choices=['SimpleAuth', 'ClientAuth'])
parser.add_argument('file', type=argparse.FileType('r'))
args = vars(parser.parse_args())

# Read the file into memory that will be sent upon client request
the_file = args['file'].read()

def handle_client_message(server, client, message):
    """Handle messages of connected clients

    :param server:
        The SSL server that the client is connected to
    :param client:
        The client_certificate if present on None for anonymous clients
    :param message:
        The message of the client

    :return:
        The file if the client sent the 'GET' command or None
    """
    if message == 'GET':
        return the_file

# Wire it all up and start the SSL server with the arguments from the command
# line
ssl_server = SslServer(args['servercert'].read(), args['serverprivkey'].read(),
                       minnissl_ca_pem, args['auth'] == 'ClientAuth')
# This is where we connect our handle_client_message to the SSL server
ssl_server.set_client_message_handler(handle_client_message)

# For low Level TCP dispatching the powerful asyncore library is used the
# TcpDispatcher is based on it. So if it is started asyncore has to be kept in
# the loop for the server to be alive and responsive
tcp_dispatcher = TcpDispatcher('', int(args['listenport']),
                               ssl_server.receive_handler)
asyncore.loop()
