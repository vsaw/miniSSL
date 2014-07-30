import os.path


def __read_pem_from_res_folder(filename):
    # todo document
    return __read_pem_file(os.path.join(__res_folder, filename))


def __read_pem_file(file):
    # todo document
    with open(file, 'r') as f:
        return f.read()

# find the res folder first
__base_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(__file__)))
__res_folder = os.path.join(__base_folder, 'res')

# Load all the files
minnissl_ca_pem = __read_pem_from_res_folder('minissl-ca.pem')
minnissl_client_key_pem = __read_pem_from_res_folder('minissl-client.key.pem')
minnissl_client_pem = __read_pem_from_res_folder('minissl-client.pem')
minnissl_server_key_pem = __read_pem_from_res_folder('minissl-server.key.pem')
minnissl_server_pem = __read_pem_from_res_folder('minissl-server.pem')
rogue_ca_pem = __read_pem_from_res_folder('rogue-ca.pem')
rogue_client_key_pem = __read_pem_from_res_folder('rogue-client.key.pem')
rogue_client_pem = __read_pem_from_res_folder('rogue-client.pem')
