

import argparse
from minissl.SslClient import SslClient
from minissl.test.PemSamples import minnissl_ca_pem
from minissl.TcpDispatcher import PickleStreamWrapper
import socket
import asyncore
import sys


def handle_connect(client):
    """Send a GET request on connect to initiate the download

    :param client:
        The client that connected
    """
    client.send('GET')


def handle_receive(client, data):
    """Just dump the data that has been received from the server

    :param client:
        The SSL Client that received the data
    :param data:
        The application data thas has been received
    """
    sys.stdout.write(data)


# Parse the command line according to the format of the assignment using the
# fabulous argparse
#
# Format:
#   ./client.py dst_ip dst_port clientcert clientprivkey
parser = argparse.ArgumentParser()
parser.add_argument('dst_ip')
parser.add_argument('dst_port', type=int)
parser.add_argument('clientcert', type=argparse.FileType('r'))
parser.add_argument('clientprivkey', type=argparse.FileType('r'))
args = vars(parser.parse_args())

# Create a asyncore powered socket to connect to the server that is given from
# the command line
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn = PickleStreamWrapper(sock)
conn.connect((args['dst_ip'], args['dst_port']))

# Start the SSL client and hook up the handler
ssl_client = SslClient(conn, minnissl_ca_pem, args['clientcert'].read(),
                       args['clientprivkey'].read())
ssl_client.set_connected_handler(handle_connect)
ssl_client.set_receive_handler(handle_receive)

# For low Level TCP dispatching the powerful asyncore library is used so
# asyncore has to be kept in the loop for the client to be alive and responsive
asyncore.loop()
